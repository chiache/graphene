#!/bin/bash

sudo rmmod graphene_sgx
sudo rmmod isgx_dummy
make || exit -1
sudo insmod linux-sgx-driver/isgx-dummy.ko || exit -1
sudo insmod graphene-sgx.ko || exit -1
