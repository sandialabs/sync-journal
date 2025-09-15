(begin
  (define meta-environment
    `(begin
       ;; --- verifiable map ---

       (define (nth-bit x n)
	     (zero? (logand (byte-vector-ref (sync-digest x) (floor (/ n 8)))
			            (ash 1 (modulo n 8)))))

       (define (sync-caar x) (sync-car (sync-car x)))

       (define (sync-cadr x) (sync-car (sync-cdr x)))

       (define (sync-cdar x) (sync-cdr (sync-car x)))

       (define (sync-cddr x) (sync-cdr (sync-cdr x)))

       (define (sync-leaf? x) (and (not (sync-null? x)) (equal? (sync-car x) (sync-cdr x))))

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
	          ((and (= (length pairs) 1) (sync-null? node))
	           (if (sync-null? (cdar pairs)) (sync-null)
		           (let ((leaf (sync-cons (caar pairs) (cdar pairs))))
		             (sync-cons leaf leaf))))
	          (else
	           (let* ((split (split-list pairs (lambda (x) (nth-bit (car x) depth))))
		              (left-old (if (sync-null? node) (sync-null) (sync-car node)))
		              (right-old (if (sync-null? node) (sync-null) (sync-cdr node)))
		              (left-new (recurse left-old (car split) (+ depth 1)))
		              (right-new (recurse right-old (cdr split) (+ depth 1))))
		         (cond
		          ((and (sync-null? left-new) (sync-null? right-new)) (sync-null))
		          ((and (sync-null? right-new) (sync-leaf? left-new)) left-new)
		          ((and (sync-null? left-new) (sync-leaf? right-new)) right-new)
		          (else (sync-cons left-new right-new)))))))))

       (define (sync-map-get root keys)
	     (let recurse ((node root) (keys keys) (depth 0))
	       (cond
	        ((= (length keys) 0) '())
	        ((sync-null? node)
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
	        ((sync-null? node) '())
	        ((sync-leaf? node) (list (cons (sync-cadr node) (sync-cddr node))))
	        (else (append (recurse (sync-car node)) (recurse (sync-cdr node)))))))

       ;; --- environment/application logic  ---

       (define (meta-bind exp)
	     (let ((a-bind (lambda (x) (expression->byte-vector x))))
	       (let p-bind ((exp exp))
	         (if (pair? exp)
		         (sync-cons (p-bind (car exp)) (p-bind (cdr exp)))
		         (let ((info (object->let exp)))
		           (if (not (undefined? (info 'source)))
		               (sync-cons (a-bind (info 'type)) (p-bind (info 'source)))  ; todo: expand
		               (sync-cons (a-bind (info 'type)) (a-bind (info 'value)))))))))

       (define (meta-find sp)
	     (let ((a-find (lambda (x) (byte-vector->expression x))))
	       (let p-find ((sp sp))
	         (if (sync-node? (sync-car sp))
		         (cons (p-find (sync-car sp)) (p-find (sync-cdr sp)))
		         (let ((type (a-find (sync-car sp)))
		               (value-sp (sync-cdr sp)))
		           (let ((value (if (sync-node? value-sp) (p-find value-sp) (a-find value-sp))))
		             (case type
		               ((procedure?) (eval value))
		               (else value))))))))

       ;; --- apply/define/set functionality ---

       (define (eval-define exp env)
	     (let ((process (lambda (x y) (cons y (sync-map-set env `((,(meta-bind x) . ,(meta-bind y))))))))
	       (if (symbol? (cadr exp))
	           (process (cadr exp) (car (meta-eval (caddr exp) env)))
	           (process (caadr exp) (car (meta-eval `(lambda ,(cdadr exp) ,@(cddr exp)) env))))))

       (define (eval-undefine exp env)
	     (cons '() (sync-map-set env `((,(meta-bind (cadr exp)) . ,(sync-null))))))

       (define (eval-definitions exp env)
	     (let ((definitions (map (lambda (x) (meta-find (car x))) (sync-map-all env))))
	       (sort! definitions (lambda (x y) (string<? (symbol->string x) (symbol->string y))))
	       (cons definitions env)))

       (define (eval-definitions-get exp env)
	     (cons env env))

       (define (eval-definitions-let exp env)
	     (let ((other-env (car (meta-eval (cadr exp) env)))
	           (other-exp (caddr exp)))
	       (cons (car (meta-eval other-exp other-env)) env)))

       (define (eval-variable exp env)
	     (cons (meta-find (cdar (sync-map-get env `(,(meta-bind exp))))) env))

       (define (eval-lambda exp env)
	     (cons (append (list '*lambda* env (cadr exp)) (cddr exp)) env))

       (define (meta-apply proc args env)
	     ;; (display "applying: ") (display proc) (display " | ") (display args) (newline)
	     (cond ((procedure? proc) (cons (apply proc args) env))
	           ((and (pair? proc) (eq? (car proc) '*lambda*))
		        (let ((bindings (map (lambda (x y) (cons (meta-bind x) (meta-bind y))) (caddr proc) args)))
		          (let loop ((exps (cdddr proc)) (env-new (sync-map-set env bindings)))
		            (if (null? (cdr exps)) (cons (car (meta-eval (car exps) env-new)) env)
			            (loop (cdr exps) (cdr (meta-eval (car exps) env-new)))))))
	           (else (error "Attempted to apply non-procedure") env)))


       ;; --- evaluation helpers ---

       (define (eval-atom exp env)
	     (cons exp env))

       (define (eval-begin exps env)
	     (let loop ((exps (cdr exps)) (env env))
	       (if (null? (cdr exps)) (meta-eval (car exps) env)
	           (loop (cdr exps) (cdr (meta-eval (car exps) env))))))

       (define (eval-quote exp env)
	     (cons (cadr exp) env))

       ;; todo: eval quasiquote

       (define (eval-if exp env)
	     (if (not (eq? (car (meta-eval (cadr exp) env)) #f))
	         (meta-eval (caddr exp) env)
	         (meta-eval (if (not (null? (cdddr exp))) (cadddr exp) #f) env)))

       (define (eval-and exp env)
	     (cons (let loop ((ls (cdr exp)))
		         (cond ((null? ls) #t)
		               ((not (meta-eval (car ls) env)) #f)
		               (else (loop (cdr ls))))) env))

       (define (eval-or exp env)
	     (cons (let loop ((ls (cdr exp)))
		         (cond ((null? ls) #f)
		               ((meta-eval (car ls) env) #t)
		               (else (loop (cdr ls))))) env))

       (define (eval-eval exp env)
	     (meta-eval (car (meta-eval (cadr exp) env)) env))

       (define (eval-apply exp env)
	     (meta-apply (car (meta-eval (cadr exp) env))
		             (car (meta-eval (caddr exp) env)) env))

       ;; --- macro-able evaluation helpers ---

       (define (eval-let exp env)
	     (if (pair? (cadr exp))
	         (let ((parameters (map (lambda (x) (car x)) (cadr exp)))
		           (arguments (map (lambda (x) (cadr x)) (cadr exp)))
		           (body (cddr exp)))
	           (cons (car (meta-eval `((lambda ,parameters ,@body) ,@arguments) env)) env))
	         (let ((name (cadr exp))
		           (parameters (map (lambda (x) (car x)) (caddr exp)))
		           (arguments (map (lambda (x) (cadr x)) (caddr exp)))
		           (body (cdddr exp)))
	           (cons (car (meta-eval `((lambda () (define (,name ,@parameters) ,@body) (,name ,@arguments))) env)) env))))

       (define (eval-cond exp env)
	     (cons (let loop ((ls (cdr exp)))
		         (cond ((null? ls) #f)
		               ((or (eq? (caar ls) 'else) (meta-eval (caar ls) env)) (meta-eval (cadar ls) env))
		               (else (loop (cdr ls))))) env))

       (define (eval-map exp env)
	     (let ((proc (car (meta-eval (cadr exp) env))))
	       (let loop ((ls (map (lambda (x) (car (meta-eval x env))) (cddr exp))) (result '()))
	         (if (null? (car ls)) (cons (reverse result) env)
		         (loop (map cdr ls) (cons (car (meta-apply proc (map car ls) env)) result))))))

       ;; todo: eval-case

       ;; --- core metacircular evaluator ---

       (define (meta-type? exp)
	     (cond ((symbol? exp) 'variable)
	           ((not (pair? exp)) 'atom)
	           ((eq? (car exp) #_quote) 'quote)
	           (else (car exp))))

       (define (meta-eval exp env)
	     ;; (display "eval: ") (display exp) (display " | ") (display env) (newline)
	     (case (meta-type? exp)
	       ((atom) (eval-atom exp env))
	       ((variable) (eval-variable exp env))
	       ((quote) (eval-quote exp env))
	       ((if) (eval-if exp env))
	       ((let) (eval-let exp env))
	       ((and) (eval-and exp env))
	       ((or) (eval-or exp env))
	       ((map) (eval-map exp env))
	       ((lambda) (eval-lambda exp env))
	       ((begin) (eval-begin exp env))
	       ((cond) (eval-cond exp env))
	       ((eval) (eval-eval exp env))
	       ((apply) (eval-apply exp env))
	       ((define) (eval-define exp env))
	       ((undefine) (eval-undefine exp env))
	       ((definitions) (eval-definitions exp env))
	       ((definitions-get) (eval-definitions-get exp env))
	       ((definitions-let) (eval-definitions-let exp env))
	       (else (meta-apply (car (meta-eval (car exp) env))
			                 (map (lambda (x) (car (meta-eval x env))) (cdr exp)) env))))))

  (define transition-function
    `(lambda (*sync-state* query)
       ,meta-environment
       (let ((result (meta-eval query (sync-cdr *sync-state*))))
	     (cons (car result) (sync-cons (sync-car *sync-state*) (cdr result))))))

  (define initial-state
    (begin
      (eval meta-environment)
      (let ((custom-list
	         '(byte-vector->hex-string
	           hex-string->byte-vector
	           byte-vector->expression
	           expression->byte-vector))
	        (keep-list
	         '(* + - / < <= = > >= abs acos acosh angle append
		         apply-values aritable? arity ash asin asinh assoc assq assv atan atanh
		         bignum bignum? boolean? byte-vector byte-vector->string
		         byte-vector-ref byte-vector? byte? caaaar caaadr caaar caadar caaddr
		         caadr caar cadaar cadadr cadar caddar cadddr caddr cadr car catch
		         cdaaar cdaadr cdaar cdadar cdaddr cdadr cdar cddaar cddadr cddar
		         cdddar cddddr cdddr cddr cdr ceiling char->integer char-alphabetic?
		         char-downcase char-lower-case? char-numeric? char-position char-upcase
		         char-upper-case? char-whitespace? char<=? char<? char=? char>=? char>?
		         char? complex complex? cons constant? copy cos cosh cyclic-sequences
		         defined? denominator display documentation eof-object? eq? equal?
		         equivalent? eqv? error eval-string even? exp expt float-vector
		         float-vector-ref float-vector? float? floor for-each format gcd gensym
		         gensym? hash-code hash-table hash-table-entries hash-table-key-typer
		         hash-table-ref hash-table-value-typer hash-table? help imag-part
		         infinite? int-vector int-vector-ref int-vector? integer->char
		         integer-decode-float integer? iterate iterator-at-end?
		         iterator-sequence iterator? keyword->symbol keyword? lcm length list
		         list-ref list-tail list-values list? log logand logbit? logior lognot
		         logxor macro? magnitude make-byte-vector make-float-vector
		         make-hash-table make-int-vector make-iterator make-list make-string
		         make-vector make-weak-hash-table map max member memq memv min modulo
		         nan nan-payload nan? negative? newline not null? number->string
		         number? numerator object->let object->string odd? pair? positive?
		         procedure-source procedure? proper-list? provide provided? quotient
		         random random-state random-state->list random-state? rational?
		         rationalize real-part real? remainder reverse round sequence?
		         signature sin sinh sqrt string string->byte-vector string->keyword
		         string->number string->symbol string-append string-copy
		         string-downcase string-position string-ref string-upcase string<=?
		         string<? string=? string>=? string>? string? substring subvector
		         subvector-position subvector-vector subvector? symbol
		         symbol->dynamic-value symbol->keyword symbol->string symbol->value
		         symbol-table symbol? syntax? tan tanh throw tree-count tree-cyclic?
		         tree-leaves tree-memq tree-set-memq truncate type-of undefined?
		         unspecified? values vector vector-dimension vector-dimensions
		         vector-rank vector-ref vector-typer vector? weak-hash-table
		         weak-hash-table? with-input-from-string zero?)))
	    (sync-map-set
	     (sync-map-new)
	     (append (map (lambda (x)
			            (cons (meta-bind x)
			                  (meta-bind (eval `(lambda args (apply ((rootlet) (quote ,x)) args))))))
		              custom-list)
		         (map (lambda (x)
			            (cons (meta-bind x) (meta-bind (eval x)))) keep-list))))))
  (define *sync-state*
    (sync-cons (expression->byte-vector transition-function) initial-state))

  "Installed metacircular interface")
