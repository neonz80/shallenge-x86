# shallenge-x86

This is my implementation of the SHAllenge (see https://shallenge.quirino.net/ and https://news.ycombinator.com/item?id=40683564). It requires an x86 CPU with the SHA256 extension.

## Compiling

shallenge-x86 requires a modern C++ compiler with C++20 support.

### Windows (Visual Studio)
Run `nmake /f Makefile.win32-msvc` or `nmake /f Makefile.win32-clang`.

### Everything else
Run `make`.

## Usage

Run the program with `shallenge username seed`, where username and seed can only contain characters from the base64 alphabet (A-Za-z0-9+/).

These options are available
  * -h/--help : Print help
  * -t/--threads : Set the number of threads. Default is the number of available cores.
  * -s/--start : Set the start position (a number from 0 to 2^48-1).
  * -e/--end : Set the end position (a number from 1 to 2^48).
  * -b/--benchmark : Run benchmark.

Username, seed, and start and end positions can not be set when running the benchmark.

The program will print the progress now and then. Set start to this number to continue from this position.

## Performance

### Intel i7-13700k (Windows + clang)
```
Running with 24 threads from 0 to 4096
00000000 e69407dd 08596643 8a925ab9 96dccfe0 8dd914b8 ddfe27f3 7e176b9f benchmark/shallenge/////////////////////AAAAAABljV0W
00000000 757ae4c1 a02fca04 06aa660a 4dd9ed53 2db70008 6fd25356 86d82c5d benchmark/shallenge/////////////////////AAAAAACLGNW/
00000000 044d9b36 726c91bc 2fcf7258 5ae75016 8e5fbc9e 05a1dc88 0f2cb312 benchmark/shallenge/////////////////////AAAAAACmymKF
58.70s 1171MH/s
```

### AMD Ryzen 7 3700X (Windows + clang)
```
Running with 16 threads from 0 to 4096
00000000 e69407dd 08596643 8a925ab9 96dccfe0 8dd914b8 ddfe27f3 7e176b9f benchmark/shallenge/////////////////////AAAAAABljV0W
00000000 757ae4c1 a02fca04 06aa660a 4dd9ed53 2db70008 6fd25356 86d82c5d benchmark/shallenge/////////////////////AAAAAACLGNW/
00000000 044d9b36 726c91bc 2fcf7258 5ae75016 8e5fbc9e 05a1dc88 0f2cb312 benchmark/shallenge/////////////////////AAAAAACmymKF
133.12s 516MH/s
```

## Credits

Written by Geir Bjerke (geir@darkside.no).

Based on code by Jeffrey Walton, Intel and Sean Gulley.
