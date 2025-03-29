#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
    #define OS "Windows"
#else
    #define OS "Linux"
#endif

void download_and_install_nmap() {
    printf("Detected OS: %s\n", OS);

#ifdef _WIN32
    printf("Downloading Nmap for Windows...\n");
    system("powershell -Command \"Invoke-WebRequest -Uri 'https://nmap.org/dist/nmap-7.94-setup.exe' -OutFile 'nmap-setup.exe'\"");

    printf("Installing Nmap...\n");
    system("start nmap-setup.exe");

    printf("Please complete the installation manually.\n");

#else
    printf("Downloading Nmap for Linux...\n");
    system("wget https://nmap.org/dist/nmap-7.94.tgz -O nmap.tar.gz");

    printf("Extracting Nmap...\n");
    system("tar -xvzf nmap.tar.gz");

    printf("Installing Nmap...\n");
    system("cd nmap-* && ./configure && make && sudo make install");

#endif
}

void run_nmap() {
    printf("Running Nmap...\n");

#ifdef _WIN32
    system("nmap -v");
#else
    system("nmap -V");
#endif
}

int main() {
    download_and_install_nmap();
    run_nmap();
    return 0;
}
