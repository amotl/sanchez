#!/usr/bin/env python
# -*- coding: utf-8 -*-

# safety runner, if steps C. or D. from normal installation fail (see INSTALL.rst)

import os, sys
sys.path.insert(0, os.path.dirname(__file__))

import sanchez.basic

def main():
    sanchez.basic.main()

if __name__ == '__main__':
    main()
