"""`python -m gargoyle` is the CLI: on a Windows Store Python the Scripts folder
that holds gargoyle.exe is usually not on PATH."""

import sys

from gargoyle.cli import main

sys.exit(main())
