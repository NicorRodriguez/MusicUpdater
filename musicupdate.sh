#!/bin/bash
# cd /home/nicolas/Music
cd $1
youtube-dl --ignore-errors --output "%(title)s.%(ext)s" --extract-audio --audio-format mp3 --download-archive downloaded.txt 'https://www.youtube.com/playlist?list=PL9qrQ6MWjdSTlVhnfilUjaL6KN2azAJGG'
# scp -P 8022 /home/nicolas/Music/* 192.168.1.225:/data/data/com.termux/files/home/storage/shared/Music
echo 'Musica actualizada :)'
