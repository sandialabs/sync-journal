(begin
  (define setup-functions
    '(begin
       (define sync-leaf (sync-cons (sync-null) (sync-null)))

       (define (object->expression obj)
	 (let* ((info (object->let obj))
		(sort
		 (lambda (obj)
		   (let ((ls (map (lambda (x) x) obj))
			 (str (lambda (x) (object->string (object->let x)))))
		     (sort! ls (lambda (x y) (string<? (str y) (str x))))))))
	   (case (info 'type)
	     ((null?) '())
	     ((pair?)
	      (cons (object->expression (car obj)) (object->expression (cdr obj))))
	     ((hash-table?)
	      (let ((flatten
		     (lambda (ls)
		       (let loop ((ls-in ls) (ls-out '()))
			 (if (null? ls-in) ls-out
			     (loop (cdr ls-in) (cons (caar ls-in) (cons (cdar ls-in) ls-out))))))))
		(cons 'hash-table
		      (flatten (sort (map (lambda (x) (cons `(quote ,(object->expression (car x)))
							    `(quote ,(object->expression (cdr x))))) obj))))))
	     ((vector?)
	      `(let* ((dim (quote ,(vector-dimensions obj)))
		      (vec (make-vector dim))
		      (cnt (let loop ((ls-in (reverse dim)) (ls-out '()) (x 1))
			     (if (null? ls-in) ls-out
				 (loop (cdr ls-in) (cons x ls-out) (* x (car ls-in)))))))
		 (let loop ((i 0) (ls (quote ,(map (lambda (x) x) obj))))
		   (if (null? ls) vec
		       (let ((indices (map (lambda (d c) (modulo (floor (/ i c)) d)) dim cnt)))
			 (begin (apply vector-set! (append (list vec) indices (list (car ls))))
				(loop (+ i 1) (cdr ls))))))))
	     ((procedure?)
	      (if (undefined? (info 'source)) (info 'value) (info 'source)))
	     ((macro?)
	      (if (undefined? (info 'source)) (info 'value) (info 'source)))
	     ((let?)
	      (let ((process
		     (lambda (binding)
		       (list 'define (car binding) (if (pair? (cdr binding))
						       `(quote ,(object->expression (cdr binding)))
						       (object->expression (cdr binding)))))))
		`(let ((env (inlet)))
		   (with-let env ,(cons 'begin (sort (map process obj)))) env)))
	     (else (info 'value)))))

       (define (object->word obj)
	 (let recurse ((expr (object->expression obj)))
	   (if (not (pair? expr))
	       (sync-cons sync-leaf (expression->byte-vector expr))
	       (sync-cons (recurse (car expr)) (recurse (cdr expr))))))

       (define (word->object word)
	 (let ((expr (let recurse ((word word))
		       (let ((left (sync-car word)) (right (sync-cdr word)))
			 (if (equal? left sync-leaf)
			     (byte-vector->expression right)
			     (cons (recurse left) (recurse right)))))))
	   (let ((env (inlet)))
	     (eval `(with-let env ,expr)))))))

  (define transition-code
    `(lambda (*sync-state* query)
       ,setup-functions
       (let* ((state-old (sync-cdr (sync-car (sync-cdr *sync-state*))))
	      (env (word->object state-old))
	      (fns '((state-index . (lambda ()
				      "(state-index) returns the current index (block number) of the state machine"
				      (byte-vector->expression
				       (sync-car (sync-car (sync-cdr *sync-state*))))))
		     (state-get . (lambda (index)
				    "(state-get index) returns the let (environment) at the historical index"
				    (let ((curr (byte-vector->expression
						 (sync-car (sync-car (sync-cdr *sync-state*))))))
				      (cond
				       ((< index 0) (error "target index cannot be negative"))
				       ((> index curr) (error "target index cannot exceed current index"))
				       (else (let loop ((i curr) (root *sync-state*))
					       (if (= i index)
						   (word->object (sync-cdr (sync-car (sync-cdr root))))
						   (loop (- i 1) (sync-cdr (sync-cdr (sync-cdr root)))))))))))
		     (state-dump . (macro (object)
				     "(state-dump expression) serializes the expression and returns a 32-byte handle"
				     (object->word object)))
		     (state-load . (lambda (word)
				     "(state-load handle) deserializes the 32-byte handle and returns an expression"
				     (word->object word))))))
	 (map (lambda (x) (varlet env (car x) (eval (cdr x)))) fns)
	 (let ((result (eval `(with-let env ,query)))
	       (state-new (object->word env)))
	   (if (equal? state-new state-old)
	       (cons result *sync-state*)
	       (let* ((transition (sync-car *sync-state*))
		      (query-word (expression->byte-vector query))
		      (i-prev (byte-vector->expression (sync-car (sync-car (sync-cdr *sync-state*)))))
		      (i-curr (expression->byte-vector (+ i-prev 1))))
		 (cons result (sync-cons transition
					 (sync-cons (sync-cons i-curr state-new)
						    (sync-cons query-word *sync-state*))))))))))

  (eval setup-functions)
  (set! *sync-state*
	(let ((transition (expression->byte-vector transition-code))
	      (query (expression->byte-vector '()))
	      (index (expression->byte-vector 0))
	      (env (object->word (inlet 'immutable! #<removed>
					'immutable? #<removed>))))
	  (sync-cons transition (sync-cons (sync-cons index env)
					   (sync-cons query (sync-null))))))

  "Installed state machine interface")
