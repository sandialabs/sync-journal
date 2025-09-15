(lambda (password)
  (begin
    (define genesis-function (byte-vector->expression (sync-car *sync-state*)))

    (define password-hash (sync-hash (expression->byte-vector password)))

    (define verifiable-structures
      '(begin
         ;; --- verifiable map ---

         (define (nth-bit x n)
	       (zero? (logand (byte-vector-ref (sync-hash x) (floor (/ n 8)))
			              (ash 1 (modulo n 8)))))

         (define (sync-caar x) (sync-car (sync-car x)))

         (define (sync-cadr x) (sync-car (sync-cdr x)))

         (define (sync-cdar x) (sync-cdr (sync-car x)))

         (define (sync-cddr x) (sync-cdr (sync-cdr x)))

         (define (sync-caddr x) (sync-car (sync-cdr (sync-cdr x))))

         (define (sync-null-pair? x)
           (and (sync-node? x) (sync-null? x)))

         (define (sync-leaf? x) (and (not (sync-null-pair? x)) (equal? (sync-car x) (sync-cdr x))))

         (define (split-list items test)
	       (let loop ((items (reverse items)) (a '()) (b '()))
	         (if (null? items) (cons a b)
	             (if (test (car items))
		             (loop (cdr items) (cons (car items) a) b)
		             (loop (cdr items) a (cons (car items) b))))))

         (define (sync-map-new) (sync-null))

         (define (sync-map-set root pairs)
	       (let recurse ((node root) (pairs pairs) (depth 0))
	         (let* ((is-leaf (sync-leaf? node))
		            (pairs (if is-leaf (cons (cons (sync-caar node) (sync-cdar node)) pairs) pairs))
		            (node (if is-leaf (sync-null) node))
		            (pairs (if (and (> (length pairs) 1) (equal? (caar pairs) (caadr pairs))) (cdr pairs) pairs)))
	           (cond
	            ((= (length pairs) 0) node)
	            ((and (= (length pairs) 1) (sync-null-pair? node))
	             (if (sync-null-pair? (cdar pairs)) (sync-null)
		             (let ((leaf (sync-cons (caar pairs) (cdar pairs))))
		               (sync-cons leaf leaf))))
	            (else
	             (let* ((split (split-list pairs (lambda (x) (nth-bit (car x) depth))))
		                (left-old (if (sync-null-pair? node) (sync-null) (sync-car node)))
		                (right-old (if (sync-null-pair? node) (sync-null) (sync-cdr node)))
		                (left-new (recurse left-old (car split) (+ depth 1)))
		                (right-new (recurse right-old (cdr split) (+ depth 1))))
		           (cond
		            ((and (sync-null-pair? left-new) (sync-null-pair? right-new)) (sync-null))
		            ((and (sync-null-pair? right-new) (sync-leaf? left-new)) left-new)
		            ((and (sync-null-pair? left-new) (sync-leaf? right-new)) right-new)
		            (else (sync-cons left-new right-new)))))))))

         (define (sync-map-get root keys)
	       (let recurse ((node root) (keys keys) (depth 0))
	         (cond
	          ((= (length keys) 0) '())
	          ((sync-null-pair? node)
	           (let loop ((keys keys) (pairs '()))
	             (map (lambda (x) (cons x (sync-null))) keys)))
	          ((sync-leaf? node)
	           (let ((key (sync-caar node)) (value (sync-cdar node)))
	             (map (lambda (x) (cons x (if (equal? x key) value (sync-null)))) keys)))
	          (else
	           (let ((split (split-list keys (lambda (x) (nth-bit x depth)))))
	             (let loop ((keys (reverse keys))
			                (left-pairs (recurse (sync-car node) (car split) (+ depth 1)))
			                (right-pairs (recurse (sync-cdr node) (cdr split) (+ depth 1)))
			                (pairs '()))
		           (cond
		            ((null? keys) pairs)
		            ((and (not (null? left-pairs)) (equal? (car keys) (caar left-pairs)))
		             (loop (cdr keys) (cdr left-pairs) right-pairs (cons (car left-pairs) pairs)))
		            ((and (not (null? right-pairs)) (equal? (car keys) (caar right-pairs)))
		             (loop (cdr keys) left-pairs (cdr right-pairs) (cons (car right-pairs) pairs))))))))))

         (define (sync-map-all root)
	       (let recurse ((node root))
	         (cond
	          ((sync-null-pair? node) '())
	          ((sync-leaf? node) (list (cons (sync-cadr node) (sync-cddr node))))
	          (else (append (recurse (sync-car node)) (recurse (sync-cdr node)))))))

         ;; --- verifiable set ---

         (define (sync-set-new)
	       (sync-map-new))

         (define (sync-set-all set)
	       (map cdr (sync-map-all set)))

         (define (sync-set-insert set items)
	       (sync-map-set set (map (lambda (x) (cons x x)) items)))

         (define (sync-set-remove set items)
	       (sync-map-set set (map (lambda (x) (cons x (sync-null))) items)))

         (define (sync-set-in set items)
	       (map (lambda (x) (equal? (car x) (cdr x))) (sync-map-get set items)))))

    (define transition
      `(lambda (*sync-state* query)
         ,verifiable-structures

         (define (valid-write? args)
	       (let loop ((ls args))
	         (if (null? ls) #t
	             (if (not (and (pair? (car ls)) (eq? (length (car ls)) 2) (symbol? (caar ls)))) #f
		             (loop (cdr ls))))))

         (define (write args)
	       (let* ((block (sync-cdr *sync-state*))
		          (state (sync-car block))
		          (index (byte-vector->expression (sync-cadr block)))
		          (pairs (map (lambda (x) (cons (expression->byte-vector (car x))
					                            (expression->byte-vector (cadr x)))) args)))
	         (cons 'success (sync-cons (sync-car *sync-state*)
				                       (sync-cons (sync-map-set state pairs)
						                          (sync-cons (expression->byte-vector (+ index 1))
							                                 block))))))

         (define (valid-read? args)
	       (and (eq? (length args) 2)
	            (and (integer? (car args)) (>= (car args) 0))
	            (and (<= (car args) (byte-vector->expression (sync-caddr *sync-state*))))
	            (symbol? (cadr args))))

         (define (read args)
	       (let loop ((block (sync-cdr *sync-state*)))
	         (let ((state (sync-car block))
		           (index (byte-vector->expression (sync-cadr block)))
		           (previous (sync-caddr block)))
	           (if (< (car args) index) (loop previous)
		           (cons (byte-vector->expression
			              (cdar (sync-map-get state (list (expression->byte-vector (cadr args))))))
		                 *sync-state*)))))

         (define (valid-digest? args)
	       (and (eq? (length args) 1)
	            (and (integer? (car args)) (>= (car args) 0))
	            (and (<= (car args) (byte-vector->expression (sync-caddr *sync-state*))))))

         (define (digest args)
	       (let loop ((block (sync-cdr *sync-state*)))
	         (let ((index (byte-vector->expression (sync-cadr block)))
		           (previous (sync-caddr block)))
	           (if (< (car args) index) (loop previous)
		           (cons block *sync-state*)))))

         (define (size)
	       (let ((block (sync-cdr *sync-state*)))
	         (cons (+ (byte-vector->expression (sync-cadr block)) 1)
		           *sync-state*)))

         (define (uninstall secret)
	       (if (not (equal? (sync-hash (expression->byte-vector (car secret))) ,password-hash))
	           (cons "Error: incorrect password" *sync-state*)
	           (cons "Uninstalled blockchain interface"
		             (sync-cons (expression->byte-vector (quote ,genesis-function)) (sync-null)))))
         
         (if (pair? query)
	         (case (car query)
	           ((write) (if (valid-write? (cdr query)) (write (cdr query))
			                (cons "Error: invalid write query" *sync-state*)))
	           ((read) (if (valid-read? (cdr query)) (read (cdr query))
			               (cons "Error: invalid read query" *sync-state*)))
	           ((digest) (if (valid-digest? (cdr query)) (digest (cdr query))
			                 (cons "Error: invalid digest query" *sync-state*)))
	           ((size) (if (eq? (length query) 1) (size)
			               (cons "Error: invalid index query" *sync-state*)))
	           ((uninstall) (if (eq? (length query) 2) (uninstall (cdr query))
			                    (cons "Error: invalid uninstall query" *sync-state*)))
	           (else (cons "Error: unrecognized query" *sync-state*)))
	         (cons "Error: badly formatted query" *sync-state*))))

    (define initial-state
      (begin
        (eval verifiable-structures)
        (sync-cons (sync-map-new) (sync-cons (expression->byte-vector 0) (sync-null)))))

    (define transition-function
      (expression->byte-vector transition))

    (set! *sync-state* (sync-cons transition-function initial-state))

    "Installed blockchain interface"))
