"""
Checks for malformed zip files. 
"""

from __future__ import annotations

import zipfile

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import IO

def zip_span(f: IO[bytes]) -> tuple[int, int] | None:
    """Find the start and end offset of a .zip file with prepended or appended data.

    If there are several concatenated zip files the span of the last zip file is given.
    If no zip file is found None is returned.
    """
    try:
        position = f.tell()
        end_record = zipfile._EndRecData(f)
    except OSError:
        return None
    if end_record is None:
        return None
    # If the Central Directory isn't at the offset the End Record gives,
    # we know there is additional data prepended to the file.    
    # The Central Directory should be immediately before the End Record,
    central_dir_offset = end_record[zipfile._ECD_LOCATION] - end_record[zipfile._ECD_SIZE]
    # But if the file is ZIP64 there's two additional ZIP64 structures in between. 
    if end_record[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:
            central_dir_offset -= (zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator)
    # The difference between the real offset and the offset the zip thinks it should be at gives the start of the file.
    start = central_dir_offset - end_record[zipfile._ECD_OFFSET]
    
    # Only thing after the End record is the zip file comment.
    # Using the length of the comment instead of the comment size field in case the file is truncated.
    end = end_record[zipfile._ECD_LOCATION] + zipfile.sizeEndCentDir + len(end_record[zipfile._ECD_COMMENT])
    # Reset position in file
    f.seek(position)
    return start, end

               
