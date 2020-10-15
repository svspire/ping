;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

;;; hexdump.lisp
;;; Prints a hexdump of a macptr in CCL.
;;; 13-Oct-2020 SVS

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

(in-package :ccl)

(defparameter *blank-character* #\. "Char to print in ASCII section for unprintable characters.")

(defMacro printable-char-p (c)
   `(and (graphic-char-p ,c) (char< ,c (code-char #x7F))))

(defMacro insert-char-code (code str idx)
   `(let ((c (code-char ,code)))
      (setf (schar ,str ,idx) (if (printable-char-p c) c *blank-character*))))

(defGeneric hexdump (address &optional len &key stream relative)
  (:documentation "Prints out memory as hex strings followed by printable ASCII chars"))

(defMethod hexdump ((address macptr) &optional (len 32) &key (stream t) (relative nil))
  (declare (fixnum len))
  (unless (macptrp address) (setf address (%int-to-ptr address)))
  (when (> len 0)
    (let* ((null-stream (null stream))
           (rowchars 16)
           (row-addr (if relative 0 (%ptr-to-int address)))
           (j) (j3)
           (val)
           (hexmap "0123456789ABCDEF")
           (hex (make-string (* rowchars 3) :initial-element #\space))
           (asc (make-string rowchars))
           (*print-circle* nil)
           (*print-pretty* nil))
      (flet ((printout ()
               (format stream "~4,'0x ~A  |~A|~%" row-addr hex asc)))
        (when null-stream (setf stream (make-string-output-stream)))
        (do ((i 0 (1+ i)))
            ((>= i len)	 
             (when (/= j (1- rowchars)) ;clr unfilled vals & print last incomplete row
               (loop for k from (+ j3 3) below (* rowchars 3)
                 do (setf (schar hex k) #\space))
               (loop for k from (1+ j) below rowchars
                 do (setf (schar asc k) #\space))
               (printout)))
          (declare (fixnum i))
          (setq val (%get-byte address i))
          (setq j (mod i rowchars))
          (insert-char-code val asc j)
          (setq j3 (* j 3))
          (setf (char hex j3) (char hexmap (/ (logand val 240) 16)))
          (setf (char hex (1+ j3)) (char hexmap (logand val 15)))	  
          (when (= j (1- rowchars))
            (printout)
            (incf row-addr rowchars)))
        (terpri stream)
        (when null-stream (get-output-stream-string stream))))))
