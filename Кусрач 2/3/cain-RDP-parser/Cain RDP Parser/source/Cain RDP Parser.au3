#Irongeek's Little Cain RDP Log Parser
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=icon.ico
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
$infilename = FileOpenDialog("Choose Cain Log File", @ProgramFilesDir & "\cain\rdp\", "Text files (*.txt)|All (*.*)")
$infile = FileOpen($infilename, 0)

;MsgBox(0, $outfile, $infile)
If $infile <> -1 Then
	$outfilename = FileSaveDialog("Choose An Output File Name", @DesktopCommonDir, "Text files (*.txt)|All (*.*)", 2) & ".txt"
	$outfile = FileOpen($outfilename, 1)
	$skipkeypress = False
	FileWrite($outfile, "Parsed Log Made From " & $infilename & @CRLF)
	While 1
		$line = FileReadLine($infile)
		If @error = -1 Then ExitLoop
		If StringLeft($line, 11) = "Key pressed" Then
			
			$line = StringRight($line, StringLen($line) - StringInStr($line, "'"))
			$line = StringLeft($line, StringLen($line) - 1)
			$line = StringReplace($line, "space", " ")
			If StringLen($line) > 1 Then
				If Not $skipkeypress Then FileWrite($outfile, @CRLF & "<" & $line & " pressed>" & @CRLF)
				$skipkeypress = True
			Else
				FileWrite($outfile, $line)
			EndIf
		ElseIf StringLeft($line, 12) = "Key released" Then
			$skipkeypress = False
			$line = StringRight($line, StringLen($line) - StringInStr($line, "'"))
			$line = StringLeft($line, StringLen($line) - 1)
			$line = StringReplace($line, "space", " ")
			If StringLen($line) > 1 Then
				FileWrite($outfile, @CRLF & "<" & $line & " released>" & @CRLF)
			Else
				;FileWrite($outfile, $line)
			EndIf
		EndIf
	WEnd
	ShellExecute($outfilename)
EndIf