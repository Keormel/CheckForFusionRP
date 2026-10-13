// guids.cpp — единственная единица трансляции, инстанцирующая GUID-ы
// известных папок (FOLDERID_*). В MinGW без INITGUID эти константы не
// определены и линковка падает с undefined reference.
#include <windows.h>
#include <initguid.h>
#include <knownfolders.h>
