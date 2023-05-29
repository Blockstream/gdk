#!/usr/bin/env bash
set -e


sed_exe=$1; shift
swig_exe=$1; shift
javac_exe=$1; shift
jar_exe=$1; shift
swig_c_file=$1; shift
dest_dir=$1; shift
swig_input=$1; shift
swig_extra_input=$1; shift
gdk_include=$1; shift

result="${dest_dir}/com/blockstream/libgreenaddress/GDK.java"
mkdir -p `dirname $result`

${swig_exe} -java -noproxy -package com.blockstream.libgreenaddress -I${gdk_include} -DGDK_API -o ${swig_c_file} -outdir ${dest_dir} ${swig_input}
${sed_exe} -i 's/GDKJNI/GDK/g' ${swig_c_file}

# Merge the constants and JNI interface into GDK.java
grep -v '^}$' ${dest_dir}/GDKJNI.java | ${sed_exe} 's/GDKJNI/GDK/g' >$result
grep 'public final static' ${dest_dir}/GDKConstants.java >>$result
cat ${swig_extra_input} >>$result
echo '}' >>$result
