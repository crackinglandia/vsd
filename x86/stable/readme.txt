'||'  '|'  .|'''.|  '||''|.   
 '|.  .'   ||..  '   ||   ||  
  ||  |     ''|||.   ||    || 
   |||    .     '||  ||    || 
    |     |'....|'  .||...|'

--
Virtual Section Dumper v2.0 x86
--

1. Introduction
2. What's VSD?
3. How to use it? (Documentation)
4. What's new?
5. License
6. Bugs, Suggestions, Comments, Features, Whatever ...
7. Project information
8. Greetings
9. Author contact information

1. [ Introduction ]

Once again, I'm here to present another tool of my own. I created this tool because I had a particular need while researching some other things. 
This is not a revolutionary tool, I know, but it fits my needs, I was going to keep it to my self but then I preferred to release it to the community.

2. [ What's VSD ]

VSD is intented to be a tool to visualize and dump the memory regions of a running 32 bits process in many ways. For example, you can dump the entire process and fix it PE header, dump a given range of memory or even list and dump every virtual section present in the process.

If you need more information just read the "How to use it?" section or visit the VSD's googlecode site listed in the "Project information" section.

3. [ How to use it? (Documentation) ]

When running, VSD lists all the running processes in a the list-view, then, you can use any of the buttons, check-boxes or the pop-up menu to interact with the processes. Here is the list of current features:

-- Main window options:

** Refresh: refreshes the processes list.

** About: displays the about window.

** Full Dump: paste header from disk: this option is only valid when you select "Full Dump" over a process. Using this, you can read the original PE header of a running process from the disk and paste it in memory before dumping. This is specially useful when dealing with packers because they usually change the data in the memory of a packed program, specially the PE Header section, to avoid the dumping process. 

** Full Dump: fix header: this option is only valid when you select "Full Dump" over a process. Using this, you can fix the Raw Offset and Virtual Offset of a process, in other words, Raw Offset == Virtual Offset.

** Exclude x64 processes: when running on Windows 7 (x64), VSD can show you the x64 processes although you can't do too much with them. If you don't want to see these processes you can use this options to filter them from the list.
You can use this feature ONLY when running with Administrative privileges (Vista/Seven/Server 2008 on both platforms, x86 and x64), if not, VSD will show you all the running processes. This is due to VSD can't obtain a handle via OpenProcess to interact with the processes (note: if you know what I'm talking about and you have an idea on how to improve/solve this problem, just email me).

** Total number of processes: prints the total number of running processes.

** Sort process by Name, PID, ImageBase or ImageSize: you can sort the list of processes by doing click in the top of every column.

-- Pop-up menu options:

** Select All: selects all the processes on the list.

** Copy to Clipboard: copies the selected items to the clipboard.

** Dump Full: dumps the entire process' memory to disk.

** Dump Partial: dumps a partial memory region to disk. You must enter a valid address and size.

** Dump Regions: displays the regions windows where you can interact with all the virtual sections of the process.

** Kill Process: terminates the execution of the selected process.

** Refresh: refreshes the process list.

-- Dump Regions window options:

** Sort virtual sections by Address, Size, Protect, State or Type: by clicking on the top of every column, you can sort the data listed in the list-view.

** Dump: dumps the selected virtual section. Not all sections can be dumped, for example, a section marked as free can't be dumped. 

** Refresh: refreshes the sections list.

** Close: closes the sections window.

4. [ What's new? ]

In this new version you can:

* Get a list of all modules in a running process.
	* Dump Full over a specific module.
	* Dump Partial over a specific module.
	* Sort modules list by Name, ImageBase or ImageSize.

* Get a list of all opened handles.

* Get a list of all threads.
	* You can terminate, suspend or resume a thread.
	* Sort the thread list by TID, Priority, TEB Address, Start Address or State.

* Patch.
	* You can search and replace bytes on memory in a running process.
	
5. [ License ]

VSD is distributed under the GNU GPL v3 license. Please, read the LICENSE file included in the .zip.

6. [ Bugs, Suggestions, Comments, Features, Whatever ... ]

If you find a bug in VSD, if you have any comments about the tool, any suggestion to improve it or if you want to request a new feature, , please, fill a ticket in the VSD's issue tracker.

If you prefer, just mail me to the address listed in the "Author(s) Contact Information".

Any comment to improve the tool is welcome! :)

7. [ Project information ]

VSD was tested under Windows XP Professional SP3, Windows 7 Ultimate (x86 & x64), wine under Ubuntu 11.04 x64.

You can visit the project at: http://code.google.com/p/virtualsectiondumper

8. [ Greetings ]

As always, I have to thank a lot of people without whom this tool had not seen the light.

Many, many thanks to:
* marciano: for being my beta tester and report a lot of bugs and features.
* MCKSys Argentina: for being my other beta tester in VSD 1.0.
* Guan De Dio: for his opinions to improve each of my tools :P
* Nacho_dj: for being a friend in ARTeam and supporting me.
* Shub-Nigurrath: for being an amazing friend, for teaching me with his tutorials and for supporting me.
* j00ru: becase he is a good friend and is always answering my questions and teaching me a lot about RE.
* deroko: for being an old friend and for teaching me a lot of stuffs during all this years.
* deepzero: for helping me with the clipboard issue.
* To all my friends in CLS, ARTeam, SnD, B@S, OpenRCE, exetools and Woodmann.

9. [ Author(s) contact information]

VSD was developed by +NCR/CRC! [ReVeRsEr]. You can contact me in the following sites:

Twitter: @crackinglandia
E-Mail: crackinglandia@gmail.com
Blog: http://crackinglandia.blogspot.com

