#!/usr/bin/python


import sys, os, string, subprocess, shutil, fileinput, multiprocessing, re, resource

def replaceAll(fd,searchExp,replaceExp):
    for line in fileinput.input(fd, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)

def prependText(filename, text) :
    data = ""
    with open(filename, 'r') as original:
        data = original.read()
    with open(filename, 'w') as modified:
        modified.write(text)
        modified.write(data)

def appendText(filename, text) :
    with open(filename, "a") as myfile:
        myfile.write(text)


home = os.getcwd()
musl = "musl-1.1.16"
muslParent = "" # musl parent directory
muslDir = ""    # musl dir (ex. musl-2.19)
buildDir = "musl-build"
installDir = os.path.dirname(home) + '/Runtime/'
commandStr = ""
commandOutput = ""
quiet = False
debug_flags = ""

for arg in sys.argv[1:]:
    if arg == '--quiet' or arg == '-q':
        quiet = True
    if arg == '--debug':
        debug_flags = "-g"

if True:

    #########################################
    #### get the locations of directories ###
    #########################################

    if not quiet:
        iput = raw_input('use {0} as the source of musl? ([y]/n):'.format(musl)).lower()
        if not iput == 'y' and not iput == '' :
            musl = raw_input('enter the musl source to install with: ')

    if not quiet:
        iput = raw_input('{0} contains musl code to compile? ([y]/n): '.format(musl)).lower()
        if not iput == 'y' and not iput == '':
            musl = raw_input('directory containing musl code to compile: ')

    if os.path.isdir(musl) :
        musl = os.path.abspath(musl)
        muslParent,muslDir = os.path.split(musl)
        print 'building in {0}: {1}'.format(muslParent, muslDir)

    if not quiet:
        iput = raw_input('use {0} as the directory to build musl in? ([y]/n): '.format(buildDir)).lower()
        if not iput == 'y' and not iput == '':
            buildDir = raw_input('the directory to build musl in:  ')

    buildDir = os.path.abspath(buildDir)
    print 'using build dir: {0}'.format(buildDir)

    if os.path.isdir(buildDir) :
        if not quiet:
            clean = raw_input('clean build (delete {0}, rerun configure, etc.)? ([y]/n): '.format(buildDir))
        else:
            clean = 'y'

        if clean == 'y' or clean == '':
            shutil.rmtree(buildDir)
            os.makedirs(buildDir)
        else :
            print 'Then just go to {0} and type make...'.format(buildDir)
            exit(0)
    else :
        os.makedirs(buildDir)

    if not quiet:
        iput = raw_input('use {0} as the directory to install musl in? ([y]/n): '.format(installDir)).lower()
        if not iput == 'y' and not iput == '':
            installDir = raw_input('the directory to install musl in:  ')

    installDir = os.path.abspath(installDir)
    print 'using install dir: {0}'.format(installDir)


if True:

    ################################
    #### doctor musl's Makefile ###
    ################################

    os.chdir(buildDir)

    cflags = '{0} -O2 -U_FORTIFY_SOURCE -fno-stack-protector'.format(debug_flags)
    extra_defs = ''
    extra_flags = '--enable-shared --disable-static'

    ##    configure
    commandStr = r'CFLAGS="{2}" {3} {0}/configure --prefix={1} {4} | tee configure.out'.format(musl, installDir, cflags, extra_defs, extra_flags)
    print commandStr
    commandOutput = subprocess.call(commandStr, shell=True)


link_binaries     = [ 'ld-linux-x86-64.so.2',
                      'libpthread.so.0',
                      'libc.so',
                      'libc.so.6',
                      'libm.so.6',
                      'libdl.so.2' ]

if True:

    for bin in link_binaries:
        if os.path.lexists(installDir + '/' + bin):
            os.unlink(installDir + '/' + bin)

        print installDir + '/' + bin + ' -> ' + buildDir + '/lib/libc.so'
        os.symlink(os.path.relpath(buildDir + '/lib/libc.so', installDir), installDir + '/' + bin)
