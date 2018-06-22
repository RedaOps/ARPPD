#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define xstr(s) str(s)
#define str(s) #s
#define L_ARP_CACHE "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)
char gateway_mac[128];
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#include "sniff.c"
char gateway_ip[128];

struct sigaction old_action;

int install_arptables();

void getGatewayIpLinux(char* gw_ip){
  //route -n | grep 'UG[ \t]' | awk '{print $2}' - command to get GW IP
  char iper[128] = "";
  FILE *fp;
  char path[1035];
  int exists = 0;

  fp = popen("route -n | grep 'UG[ \t]' | awk '{print $2}'", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    strcat(iper, path);
  }

  strncpy(gw_ip, iper, 15);
  strtok(gw_ip, "\n");
  printf("%sGATEWAY IP ADDRESS SAVED: %s%s%s\n", KWHT, KCYN, gw_ip, KWHT);

}

void *allowAllConnections(void *arg)
{
  FILE *fp;
  char path[1035];
  int exists = 0;
    while(1)
    {
        sleep(300);
        fp = popen("arptables -P INPUT ACCEPT && arptables --flush && ip -s neighbour flush all", "r");
        if (fp == NULL) {
          printf("Failed to run command\n" );
          exit(1);
        }
        printf("ARP Refresh: Allowing all connections!\n");
    }
    return 0;
}

void sigint_handler(int sig_no){
  FILE *fp;
  char path[1035];
  int exists = 0;
  char j[1024] = "";
  snprintf(j, sizeof(j), "arp -d %s && arptables -P INPUT ACCEPT && arptables --flush && ip -s neighbour flush all && echo done", gateway_ip);

  fp = popen(j, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    printf("%s", path);
  }

  printf("Successfully exited. Flushed ARP table and enabled all ARP connections!\n");
  exit(0);
}

int saveGatewayMacLinux(){

//Scan through the ARP Table

FILE *arpCache = fopen(L_ARP_CACHE, "r");
    if (!arpCache)
    {
        perror("Arp Cache: Failed to open file \"" L_ARP_CACHE "\"");
        return 1;
    }

    /* Ignore the first line, which contains the header */
    char header[ARP_BUFFER_LEN];
    if (!fgets(header, sizeof(header), arpCache))
    {
        return 1;
    }


    char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN];
    int count = 0;
    while (3 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr, device))
    {
        if(strncmp(ipAddr, gateway_ip, 15) == 0){
		        strncpy(gateway_mac, hwAddr, 17);
        }
    }

	printf("%sGATEWAY MAC ADDRESS SAVED: %s%s%s\n", KWHT, KCYN, gateway_mac, KWHT);
	fclose(arpCache);
	return 0;
}



int main(int argc, char ** argv){
  //Save Gateway IP and MAC
  getGatewayIpLinux(gateway_ip);
  saveGatewayMacLinux();

  //Allow all connections every 5 minutes and on exit
  pthread_t tid;
  pthread_create(&tid, NULL, &allowAllConnections, NULL);
  struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;
    sigaction(SIGINT, &action, &old_action);

  //Check for arptables installation
  install_arptables();
  printf("%sWARNING: %sBefore starting this script, make sure there are currently\nno ARP Poisoning attacks on this network!\n(Restart router to be sure)\nPress Enter to continue...\n", KRED, KWHT);
  char enter = 0;
  while (enter != '\r' && enter != '\n') { enter = getchar(); }
	printf("%sLinux ARP Poisoning defender started... Scanning for MITM attacks...%s\n", KGRN, KWHT);
  sniffARPPackets(gateway_mac, gateway_ip);
	return 0;
}

int install_arptables(){
  FILE *fp;
  char path[1035];
  int exists = 0;

  /* Open the command for reading. */
  fp = popen("dpkg -l | grep arptables", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    exists = 1;
  }

  /* close */
  pclose(fp);

  if(exists == 1){
    printf("arptables already installed!\n");
  }else{
    printf("%sPlease install arptables before running this script.\nInstall with: sudo apt-get install arptables\n%s", KRED, KWHT);
    exit(0);
  }
  return 1;
}
