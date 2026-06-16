"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    from .cli import main
    main()
