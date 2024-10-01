rule autoyar_exe_8724823c104b {
   meta:
      description = "Detection for Ease Paint Solutions Dropper (8724823c104bbb4ec3f7192eac1c97b482fd129e7550201cb77cae0c066ab09d.exe)"
      author = "Enigmatikk"
      reference = "Malware Analysis Report: Ease Paint Solutions Dropper"
      date = "2024-10-01"
      hash1 = "8724823c104bbb4ec3f7192eac1c97b482fd129e7550201cb77cae0c066ab09d"
      hash256 = "8724823c104bbb4ec3f7192eac1c97b482fd129e7550201cb77cae0c066ab09d"
      md5 = "9240aca1f525f6e95cda49f229c524a9"
      sha1 = "2e8c54593b569fe814e1832b9178458a1a29502b"

   strings:
      $s1 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii /* score: '16.00'*/
      $s2 = "BackgroundSizing=\"{TemplateBinding BackgroundSizing}\"" fullword ascii /* score: '11.00'*/
      $s3 = "<Setter Target=\"MultiSelectCheckBox.Visibility\" Value=\"Visible\" />" fullword ascii /* score: '14.00'*/
      $s4 = "<Setter Property=\"Foreground\" Value=\"{ThemeResource ComboBoxForeground}\" />" fullword ascii /* score: '9.00'*/
      $s5 = "Storyboard.TargetName=\"PopupBorder\"" fullword ascii /* score: '17.00'*/
      $s6 = " FASTOEM=1 /qn" fullword wide /* score: '8.00'*/
      $s7 = "<!-- Changed background color, stroke color and CheckGlyph, Removed ContentPrensenter. -->" fullword ascii /* score: '24.00'*/
      $s8 = "instname-target.msi" fullword wide /* score: '21.00'*/
      $s9 = "C:\\ReleaseAI\\stubs\\setup\\ExternalUiManager.cpp" fullword wide /* score: '16.00'*/
      $s10 = "IsHorizontalRailEnabled=\"{TemplateBinding ScrollViewer.IsHorizontalRailEnabled}\"" fullword ascii /* score: '11.00'*/

      //IOC patterns
      $ioc1 = "0.0.0.0"
      $ioc2 = "ExtractionFolder=[AppDataFolder]Xiamen Baishengtong Software Technology Co. Ltd\\Ease Paint Solutions 2.2.0.0\\install"
      $ioc3 = "2.2.0.0"

   condition:
      uint16(0) == 0x5a4d and filesize < 17234KB and filesize > 14100KB and
      3 of ($ioc*) and
      all of ($s*)
}