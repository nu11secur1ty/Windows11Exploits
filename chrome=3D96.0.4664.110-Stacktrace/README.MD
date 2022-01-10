## chrome=96.0.4664.110

## [Software](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/Microsoft/2022/chrome%3D96.0.4664.110-Stacktrace/PoC/chromedriver_win32.zip)

## [From-Google](https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B24F3351A-A4AF-042A-4DA6-AEE56456DDA4%7D%26lang%3Dbg%26browser%3D4%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3D-statsdef_1%26installdataindex%3Ddefaultbrowser/update2/installers/ChromeStandaloneSetup.exe)

## [Vendor](https://chromedriver.chromium.org/downloads)
```cmd
  (Session info: chrome=96.0.4664.110)
Stacktrace:
Backtrace:
        Ordinal0 [0x00286903+2517251]
        Ordinal0 [0x0021F8E1+2095329]
        Ordinal0 [0x00122848+1058888]
        Ordinal0 [0x00115AD4+1006292]
        Ordinal0 [0x00115716+1005334]
        Ordinal0 [0x00114DDA+1002970]
        Ordinal0 [0x00113F8D+999309]
        Ordinal0 [0x00114357+1000279]
        Ordinal0 [0x0011F131+1044785]
        Ordinal0 [0x001154D9+1004761]
        Ordinal0 [0x001160E0+1007840]
        Ordinal0 [0x0011572A+1005354]
        Ordinal0 [0x00114DDA+1002970]
        Ordinal0 [0x00113F8D+999309]
        Ordinal0 [0x00114246+1000006]
        Ordinal0 [0x00123E1A+1064474]
        Ordinal0 [0x0017616D+1401197]
        Ordinal0 [0x001664D3+1336531]
        Ordinal0 [0x00175BBF+1399743]
        Ordinal0 [0x0016639B+1336219]
        Ordinal0 [0x001427A7+1189799]
        Ordinal0 [0x00143609+1193481]
        GetHandleVerifier [0x00415904+1577972]
        GetHandleVerifier [0x004C0B97+2279047]
        GetHandleVerifier [0x00316D09+534521]
        GetHandleVerifier [0x00315DB9+530601]
        Ordinal0 [0x00224FF9+2117625]
        Ordinal0 [0x002298A8+2136232]
        Ordinal0 [0x002299E2+2136546]
        Ordinal0 [0x00233541+2176321]
        BaseThreadInitThunk [0x76416739+25]
        RtlGetFullPathName_UEx [0x77D38AFF+1215]
        RtlGetFullPathName_UEx [0x77D38ACD+1165]
        (No symbol) [0x00000000]
```

## Description:
Cannot determine loading status from disconnected - received Inspector: 
"raise exception_class(message, screen, stacktrace) selenium.common.exceptions.WebDriverException: Message: unknown error: net::ERR_NAME_NOT_RESOLVED" Detached event.
The attacker can use this issue to find a vulnerability and he can buffer overflowing the app to get privileges of the system with administrative access!
NOTE: Patch your ChromeDriver for Windows 11 with the latest version!

## [PoC](https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/Microsoft/2022/chrome%3D96.0.4664.110-Stacktrace/PoC)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/Microsoft/2022/chrome%3D96.0.4664.110-Stacktrace/PoC/Stacktrace-chromedriver-PoC.gif)

## Reproduce:
[href](https://github.com/nu11secur1ty/CVE-nu11secur1ty/edit/main/vendors/Microsoft/2022/chrome=96.0.4664.110-Stacktrace)

## Proof and exploit:
[href0](https://streamable.com/1r4cvx)

[href1](https://streamable.com/ofbmhz)

## Conclusion:
- - - UPDATE to the latest version of your chrome and ChromeDriver!
- KR @nu11secur1ty
