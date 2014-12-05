#!/bin/bash

kill $(ps aux | grep '[f]uzzer' | awk '{print $2}')
rm ./log/*
rm ./pid/*

