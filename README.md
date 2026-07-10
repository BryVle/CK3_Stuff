Please note that this whole thing was created with the help of AI.
It is way above my own pay grade.

So don't expect anything beyond a novelty.


Here is how it works and how to use it:
Inside the CK3X folder, open the dist folder and drag the contents into your CK3's root folder. So the resulting file structure should look something like so;
binaries
CK3X
clausewitz
game
jomini
launcher
CK3X.exe


Then, launch CK3X.exe. This will ask Steam to launch the game as normal, and that's it.
Once the game is actually running, sapphicHeritage.dll will be loaded from the CK3X's mod folder and modify the game's runtime memory that is responsible for the code that blocks female characters from being assigned as the father of a child. Many mods have worked around this issue by hacking together chains of events, and they work great, but can be a little janky. This approach instead removes the hardcoded block on the game engine itself, so a normal mod could now actually just have a female character impregnate another without those hacky workarounds.
