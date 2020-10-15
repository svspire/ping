;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

;;; ping.lisp
;;; 13-Oct-2020 SVS
;;; Implements ICMP (ping) in CCL

;; Copyright (c) 2020, Shannon Spires
;; All rights reserved.

;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are
;; met:

;;   * Redistributions of source code must retain the above copyright
;;     notice, this list of conditions and the following disclaimer.

;;   * Redistributions in binary form must reproduce the above copyright
;;     notice, this list of conditions and the following disclaimer in
;;     the documentation and/or other materials provided with the
;;     distribution.

;;   * Neither Shannon Spires nor the names of its contributors of the
;;     software may be used to endorse or promote products derived from
;;     this software without specific prior written permission.

;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;; HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;; LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


(in-package :ping)

(defun default-ping-id ()
  (logand (ccl::getpid) #xFFFF))

(defparameter *ping-debug* nil "Set to true to enable debugging.")

(defmacro when-debugging (&body body)
  `(when *ping-debug*
     ,@body))

(defclass icmp-socket (ccl::ip-socket ccl::device-mixin) ())

(defun checksumbuffer (ptr len)
  "I don't know how important this algorithm is, but I'll do it like Quinn did it."
  (let ((sum 0)
        (offset 0))
    (dotimes (i (/ len 2))
      (incf sum (ccl:%get-word ptr offset))
      (incf offset 2))
    (setf sum (+ (ash sum -16) (logand sum #xFFFF)))
    (+ sum (ash sum -16))
    (logand (lognot sum) #xFFFF)))

(defun host-as-inet-host (host)
  (etypecase host
    (integer (ccl::htonl host))
    (string (or (and (every #'(lambda (c) (position c ".0123456789")) host)
		     (ccl::_inet_aton host))
                (ccl:resolve-address :host host :address-family :internet)))))

(defun sendicmp (socket host sequence-number id)
  (ccl:rlet ((ping-data icmp)
         (sin #>sockaddr_in))
    (let ((fd (ccl::socket-device socket)))
      (setf (ccl:pref ping-data :icmp.icmp_type) #$ICMP_ECHO) ; ping request
      (setf (ccl:pref ping-data :icmp.icmp_code) 0)
      (setf (ccl:pref ping-data :icmp.icmp_cksum) 0) ; dummy checksum to pass to #'checksumbuffer
      (setf (ccl:pref ping-data :icmp.icmp_hun.ih_idseq.icd_id) id)
      (setf (ccl:pref ping-data :icmp.icmp_hun.ih_idseq.icd_seq) sequence-number)

      (setf (ccl:pref ping-data :icmp.icmp_cksum) (checksumbuffer ping-data (ccl::record-length :icmp)))
     
      (when-debugging
        (format t "~%Sent packet:~%")
        (ccl::hexdump ping-data (ccl::record-length :icmp)))

      (setf (ccl:pref sin #>sockaddr_in.sin_family) #$AF_INET)
      (setf (ccl:pref sin #>sockaddr_in.sin_addr.s_addr) (host-as-inet-host host) )
      (setf (ccl:pref sin #>sockaddr_in.sin_port) 0)
      
      (ccl::socket-call socket "sendto"
                   (ccl::with-eagain fd :output
                     (ccl::c_sendto fd ping-data (ccl::record-length :icmp) 0 sin (ccl::record-length #>sockaddr_in)))))))

(defun wait-for-icmp-response (socket id &optional (seq-number 0) start-time seconds-to-wait)
  "Waits for ICMP responds. Waits forever if seconds-to-wait is nil. Otherwise wait no longer than that number of seconds."
  (let ((pType nil)
        (got-response nil)
        (response-seq-number nil)
        (responder nil)
        (reason nil)
        (hlen nil)
        (turnaround-time nil)
        (numbytes nil)
        (ping-data-ptr nil)
        (max-response-size 100))
    (ccl:%stack-block ((bufptr max-response-size))
      (flet ((%receive-from (fd) ; could have called receive-from here but I wanted to avoid all that copying
               (ccl:rlet ((sockaddr :sockaddr_in)
                      (namelen :signed))
                 (setf (ccl:pref sockaddr :sockaddr_in.sin_family) #$AF_INET)
                 (setf (ccl:pref sockaddr :sockaddr_in.sin_addr.s_addr) #$INADDR_ANY)
                 (setf (ccl:pref sockaddr :sockaddr_in.sin_port) 0)
                 (setf (ccl:pref namelen :signed) (ccl::record-length :sockaddr_in))
                 (setq numbytes (ccl::socket-call socket "recvfrom"
                                                  (ccl::with-eagain fd :input
                                                    (ccl::c_recvfrom fd bufptr max-response-size 0 sockaddr namelen))))
                 (when (> numbytes 0)
                   (ccl::ntohl (ccl:pref sockaddr :sockaddr_in.sin_addr.s_addr))))))
        ; look for a packet
        (let ((fd (ccl::socket-device socket)))
          (cond (seconds-to-wait
                 (multiple-value-bind (win timedout error)
                                      (ccl:process-input-wait fd (* 1000 seconds-to-wait))
                   (if win
                       (setf responder (%receive-from fd))
                       (unless timedout
                         (ccl::stream-io-error socket (- error) "read")))))
                (t (setf responder (%receive-from fd)))))

        (cond (responder ; got a response
               (setf turnaround-time (- (get-internal-real-time) start-time))
               (when-debugging
                 (ccl::hexdump bufptr numbytes))
               (setf hlen (ash (ccl:pref bufptr :ip.ip_hl) 2)) ; bufptr points to an ip packet. Figure out header length. (Ignore options if any.)
               (setf ping-data-ptr (ccl:%inc-ptr bufptr hlen))
               (setf ptype (ccl:pref ping-data-ptr :icmp.icmp_type))
               ;(format t "~%ICMP type = ~D" ptype)
               (setf response-seq-number (ccl:pref ping-data-ptr :icmp.icmp_hun.ih_idseq.icd_seq))
               (when-debugging (format t "~% response-seq-number: ~D" response-seq-number))
               
               (setf got-response (and (= ptype #$ICMP_ECHOREPLY)
                                       (= (ccl:pref ping-data-ptr :icmp.icmp_hun.ih_idseq.icd_id) id)
                                       (= response-seq-number seq-number)
                                       ))
               (unless got-response
                 (cond ((/= ptype #$ICMP_ECHOREPLY)
                        (setf reason :bad-ptype))
                       ((/= (ccl:pref ping-data-ptr :icmp.icmp_hun.ih_idseq.icd_id) id)
                        (when-debugging (format t "~%PID received = ~D" (ccl:pref ping-data-ptr :icmp.icmp_hun.ih_idseq.icd_id)))
                        (setf reason :bad-pid)) ; It's perfectly reasonable for this to happen:
                                                ;  If some other process issues a ping and we see the response (which we might), we should ignore it.
                       ((/= response-seq-number seq-number)
                        (when-debugging (format t "~%seq-number = ~D" seq-number))
                        (setf reason :bad-seqnum))
                       (t (setf reason :unknown)))))
              
              (t (setf reason :timeout)))
        (if got-response
            (values responder (float (/ turnaround-time internal-time-units-per-second)))
            (values nil reason))))))

(defun make-icmp-socket (&rest keys &aux (fd -1))
  (unwind-protect
    (let (socket)
      (setq fd (ccl::socket-call nil "socket"
			    #+IGNORE (ccl::c_socket #$AF_INET #$SOCK_RAW #$IPPROTO_ICMP) ; requires root
                            (ccl::c_socket #$AF_INET #$SOCK_DGRAM #$IPPROTO_ICMP)
                            ))
      
      (setq socket (make-instance 'icmp-socket
                     :device fd
                     :keys keys))
      (apply #'ccl::set-socket-options socket keys)
      (setq fd -1)
      socket)
    (unless (< fd 0)
      (ccl::fd-close fd))))

; This function is designed to be used from a program, for example to test the availability of
;   a machine before sending data to it.
(defun %ping (host &key (sequence-number 0) (seconds-to-wait nil) (id (default-ping-id)))
  "Pings host, waiting up to seconds-to-wait seconds (or forever if that's nil) for a response.
   If response comes back within that time and looks okay, return 
      (values responder-address response-time). Response-time is in seconds.
   Else return
     (values nil reason)."
  (let ((socket (make-icmp-socket)))
    (setq host (ccl:lookup-hostname host)) ; DNS lookup if necessary
    (let ((start-time (get-internal-real-time)))
      (setf id (logand #xFFFF id))
      (sendicmp socket host sequence-number id)
      (wait-for-icmp-response socket id sequence-number start-time seconds-to-wait))))

; Interactive version of ping. Call it from the listener.
(defun ping (host &key (count 5) (interval 1) (seconds-to-wait 5) (id (default-ping-id)))
  "Ping with a user interface.
  :count is equivalent to the -c switch on the Unix command.
  :interval is equivalent to the -i switch on the Unix command."
  (let ((status nil)
        (seq-number 0)
        (lost 0)
        (success nil))
    (setq host (ccl:lookup-hostname host))
    (loop while (< seq-number count) do
      (format t "~%Sending ping...") (force-output t)
      (multiple-value-setq (success status)
        (%ping host :sequence-number seq-number :id id :seconds-to-wait seconds-to-wait))
      (cond (success
             (format t "~%!!!Got ICMP!!!!")
             (format t "~%ICMP from ~A" (ccl:ipaddr-to-dotted success))
             (format t "~%Turnaround time ~S seconds" status))
            (T
             (incf lost)
             (if (eql status :timeout)
                 (format t "~%Timeout.")
                 (format t "~%Bad response: ~S" status))))
      (sleep interval)
      (incf seq-number))
    (format t "~%Ping complete. ~D packets sent. ~D packets lost. ~S% packet loss."
            seq-number lost (float (/ (* lost 100) seq-number)))))

; (ping:ping "www.google.com")
; (ping:ping "www.yahoo.com")

