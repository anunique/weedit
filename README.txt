this is weedit 3.0.0 readme
weedit is a file duplicate finder thats using checksums to check for duplicates. it got an automaintaining 
database. weedit will detect if a file disappears or got modified and will update entries on the fly.

so far have fun playing with it.

feel free to donate to:
BTC: 17dMvPPcYAznrwrgbWQYf6QNgBpoX7x2f2

---

USAGE: ./weedit -cdflnpqstuv [[DB1] [DB2]] [db to load] [db to save] [directory to scan]
        c [DB1] [DB2] = compare DB1 with DB2
        d = scan for dupes saved in DB
        f = force weedit to calculate md5 and sha1
        l [DB] = load name given
        n = dont add files to DB (dont save it)
        p = print database
        q = quiet mode
        s [DB] = save name given (else save name = load name)
        t = truncate database (dont load it)
        u = unlink (delete) new dupes
        v = show version information
