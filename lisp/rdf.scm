(begin
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

  (define transition-function
    `(lambda (*sync-state* query)
       ,verifiable-structures

       (define (select s p o)
	     (let* ((smg (lambda (m k) (cdar (sync-map-get m (list k)))))
		        (ebv (lambda (x) (expression->byte-vector x)))
		        (bve (lambda (x) (byte-vector->expression x)))
		        (key (ebv (list (if (null? s) () s) (if (null? p) () p) (if (null? o) () o))))
		        (tab (ebv (string->symbol (string (if (null? s) #\- #\s)
						                          (if (null? p) #\- #\p)
						                          (if (null? o) #\- #\o))))))
	       (cons (map bve (sync-set-all (smg (smg (sync-cdr *sync-state*) tab) key)))
		         *sync-state*)))

       ;; we can definitely clean this up...
       (define (handle sync-set-operation s p o)
  	     (let ((sso (lambda (s x) (sync-set-operation s (list x))))
	           (sms (lambda (m k v) (sync-map-set m (list (cons k v)))))
  	           (smg (lambda (m k) (cdar (sync-map-get m (list k)))))
  	           (ebv (lambda (x) (expression->byte-vector x)))
  	           (expanded `((spo (,s ,p ,o))
			               (sp- (,s ,p ()))
			               (s-o (,s () ,o))
			               (-po (() ,p ,o))
			               (s-- (,s () ()))
			               (-p- (() ,p ()))
			               (--o (() () ,o))
			               (--- (() () ())))))
  	       (cons (list s p o)
  		         (let loop ((ls expanded) (rdf-state (sync-cdr *sync-state*)))
  		           (if (null? ls) (sync-cons (sync-car *sync-state*) rdf-state)
  		               (loop (cdr ls)
  			                 (sms rdf-state (ebv (caar ls))
  				                  (sms (smg rdf-state (ebv (caar ls))) (ebv (cadar ls))
				                       (sso (smg (smg rdf-state (ebv (caar ls))) (ebv (cadar ls)))
					                        (ebv (list s p o)))))))))))

       (case (car query)
  	     ((select) (apply select (cdr query)))
  	     ((insert) (apply handle (cons sync-set-insert (cdr query))))
  	     ((remove) (apply handle (cons sync-set-remove (cdr query))))
  	     (else `("Error: bad command" ,*sync-state*)))))

  (define initial-state
    (begin 
      (eval verifiable-structures)
      (sync-map-set (sync-map-new)
  		            (map (lambda (x) (cons (expression->byte-vector x) (sync-set-new)))
  			             '(spo sp- s-o -po s-- -p- --o ---)))))

  (define *sync-state*
    (sync-cons (expression->byte-vector transition-function) initial-state))

  "Installed RDF interface")
