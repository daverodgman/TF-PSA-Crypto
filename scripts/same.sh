#!/bin/sh
REFERENCE=cec4ef99b591a49482ede9eb1a47c1ff599e8be0
git diff-tree --stat HEAD $REFERENCE
