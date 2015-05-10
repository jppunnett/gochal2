# gochal2
Go Challenge 2

# Lessons
After posting my solution and looking at winner's solution, I've learned,

* I'm generating the server's key pair only once so every client connection
usings the same public key. Is this a bad?

* Code could be more efficient if I'd used precomputed keys

* My Read() func does not handle EOF or cases where bytes remaining to read, but
caller's buffer small.

* I need to read up pn embedded struct. My code for read/write/closer could be
made more simple
 