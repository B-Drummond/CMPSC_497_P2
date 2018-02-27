Command line used to find this crash:

/home/ugrads/bld5292/CMPSC_497/CMPSC_497_P2/afl-2.52b/afl-fuzz -i /home/ugrads/bld5292/CMPSC_497/CMPSC_497_P2/input_files/ -o /home/ugrads/bld5292/afl_output/ ./cmpsc497-p1 set user passwd @@

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 50.0 MB.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
