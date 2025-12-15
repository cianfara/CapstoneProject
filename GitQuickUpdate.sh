#ignore
#!/bin/bash

Green="\033[0;32m"
White="\033[1;37m"
Space="\t\t\t\t\t\t\t"
Format=${Space}${Green}
Home=$(pwd)												#Executes Pwd so the Dir does not change while running
DefaultGitMsg="Default commit message"									#This is used if the -m flag is not given

if [[ $1 = "help" ]]
then
	cat testScrMan
	exit 0
fi

if [[ $1 == *"i"* ]]
then
	cd $Home											# CD to script root for no apparent reason 
	./funProjectAnalyze.sh										#(Huge problem having both modes in one script. Mostly related to args now working)
	exit 0              										# Exit when the functional script is closed
fi

echo "Root directory is set to: ${Home}"
if [[ $1 != *"q"* ]]
then
	cat startupData |
	while read stuffToDo
	do
        	echo -e "${stuffToDo}${Format}[OK]${White}" 						#Loops through a textfile inserting it before the [OK]
		sleep 0.5
	done
fi


find . -name "*.hs" |
while read checkHs
do
        ghc -fno-code $(basename "$checkHs") 2>> error.log       				       #Copies just the error. Use &>> for both the error and regular output
done

echo "Creating working tree log"
find -type d | sed "/git/d" > workingTree.log								#Sed here removes any hidden git folders

if [[ $1 == *"s"* ]]
then
	echo "What tag should I look for?"
	read toFind
	grep --exclude="$toFind" -r "$toFind" . > $toFind
fi

if [[ $1 == *"d"* ]]
then
        echo "Please enter a file name"
        read fileName											#Could get input with flags although cleaner to do while running
        echo "Enter default text"
        read defaultText
        cat workingTree.log |
        while read targetDir 										#ToDo check if file already exists. Have flag for overwrite
        do
		
                echo "Creating file ${fileName} in ${targetDir}"
                cd $targetDir
                touch ${fileName}
		if [[ $1 == *"a"* ]]
		then
			echo ${defaultText} >> ${fileName}
		else
                	echo ${defaultText} > ${fileName}
		fi
                cd ${Home}
        done
fi

if [[ $1 == *"u"* ]]
then
	echo "Staring Add Files"
	git status -s | grep "?? \| M \|M \|MM " | sed 's/.\{3\}//' |  			  	        	 #Sed removes the first three spaces
	while read stuffToAdd
	do
		find -name $(basename ${stuffToAdd}) -printf '%h\n' |  						#This finds the files and leaves just the path
		while read inDir
		do
			cd ${inDir}
			if [ -e $(basename "$stuffToAdd") ]							#File does not exist
			then
				CheckTag=$(grep "#ignore" $(basename "$stuffToAdd")) 				#Going two sub-shells deep
				if [ "$CheckTag" != "#ignore" ]
				then
						echo "Adding $(basename "$stuffToAdd") in ${inDir}"
							git add $(basename "$stuffToAdd")                       #Basename to get rid of the path
				else
						echo "Found #ignore tag: $(basename "$stuffToAdd") ignored"
				fi
			fi
			cd $Home
		done
		cd $Home
	done

	echo "Starting remove files"
	git status -s | grep " D " | sed 's/.\{3\}//' | 							#Space needed
	while read stuffToRm
	do
			git rm -f ${stuffToRm}
	done
fi

echo -e "\n\n\nUpdated git status (To Update please use the -u flag)"						#All code that changes files should be above here
echo "---------------------------------"
git status

if [[ $1 == *"c"* ]]
then
        if [[ $1 == *"m"* ]]
        then
                echo "Sending commit with message ${2}"
                git commit -m "${2}"
	else
		echo "Sending commit with default message"
        	git commit -m "$DefaultGitMsg"									#Set at the top of the program
        fi
fi

if [[ $1 == *"p"* ]]
then
	git push
fi
