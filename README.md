# gochal2
Go Challenge 2

# Lessons
After posting my solution and looking at winner's solution, I've learned,

* I'm generating the server's key pair only once so every client connection
uses same server public key. Is this a bad?

* Code could be more efficient if I'd used precomputed keys; would need to pre-
compute if this was a published library.

* My Read() func does not handle EOF or cases where bytes remaining to read, but
caller's buffer small.

* I need to read up on embedded struct. My code for read/write/closer could be
made more simple

* It appears to be a Go convention to separate with a blank line golang.org
packages from standard packages. Why?

* In keeping with Dial interface, it should really return a connection.

* I like the way the winner used box.Precompute on the struct field; it's cleaner
then using a local variable.

* Write should not return the length of the encrypted message. It should return 
the the length of the encrypted message less the overhead otherwise the caller
be confused. 