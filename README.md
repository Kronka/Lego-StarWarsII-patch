# Lego-StarWarsII-patch
Search for problem areas of the game. And it needs to be fixed!

A series of video games "Lego" - Star Wars: The Skywalker Saga, Star Wars: The Force Awakens, Star Wars: The Video Game, Star Wars II: The original Trilogy, Star Wars:The Complete Saga has crashes on Windows 7/8/10/11.  
This repository is aimed at Lego Star Wars II. But I'm sure the rest of the Lego series games have similar problems.
I would like to try to fix it, but I need the help of society. So far we have a small debug that records the crash address.  
Researches:  
- My friend had a game crash on the first mission in the cutscene. There is a problem in the amd driver in the file nvd3dum.dll , at 0x5E0A61BC (EXCEPTION_ACCESS_VIOLATION)  
- I caught a game crash once at 0x5481CA (qmemcpy, 0x0 nullptr)
