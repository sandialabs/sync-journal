(begin
  (define (reduce proc start iterable)
    (let loop ((ls (map values iterable)) (result start))
      (if (null? ls) result
	      (loop (cdr ls) (proc result (car ls))))))

  (define (filter proc iterable)
    (let loop ((ls (map values iterable)) (result '()))
      (if (null? ls) (reverse result)
	      (loop (cdr ls) (if (proc (car ls)) (cons (car ls) result) result)))))

  (define (range start end step)
    (let loop ((i start) (result '()))
      (if (>= i end) (reverse result)
	      (loop (+ i step) (cons i result)))))

  (define (apropos x)
    (let loop ((ls (definitions)) (result '()))
      (if (null? ls) (reverse result)
	      (let ((description (object->string (help (car ls)))))
	        (if (string-position x description)
		        (loop (cdr ls) (cons description result))
		        (loop (cdr ls) result))))))

  "Installed metacircular utilities")
