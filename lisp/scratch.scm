(begin
  (define transition-function
    '(lambda (*sync-state* query)
       (cond
	    ((and (pair? query) (eq? (length query) 2) (eq? (car query) 'write) (string? (cadr query)))
	     (cons 'success (sync-cons (sync-car *sync-state*) (expression->byte-vector (cadr query)))))
	    ((and (pair? query) (eq? (length query) 1) (eq? (car query) 'read))
	     (cons (byte-vector->expression (sync-cdr *sync-state*)) *sync-state*))
	    (else (cons "Error: please enter either (read) or (write \"some string\")" *sync-state*)))))

  (define initial-state "")

  (define *sync-state*
    (sync-cons (expression->byte-vector transition-function)
	           (expression->byte-vector initial-state)))

  "Installed scratch interface")
