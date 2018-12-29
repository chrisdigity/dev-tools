/* txbot.c  Sends transaction to Mochimo peers.
 *
 * Copyright (c) 2018 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 28 December 2018
 *
 * NOTE: To compile without a script:
 *
 *     viz. Borland C++ 5.5.
 *     bcc32 -DWIN32 txbot.c wots.obj sha256.obj
 *
 *     Unix-like:
 *     cc -DUNIXLIKE -DLONG64 -c sha256.c wots.c
 *     cc -o txbot -DUNIXLIKE -DLONG64 txbot.c
 *                                   ^
 *                  Remove if your longs are not 64-bit.
*/


/* Maximum times through the loop before exiting and restarting. */
#define MAXLOOPS 200
/* Maximum number of peer connection attempts before
 * bailing and recreating peer list.
 */
#define MAXFAILS 16
#define CORELISTLEN  32
#define HASHLEN 32  /* for types.h */

#define VEOK        0      /* No error                    */
#define VERROR      1      /* General error               */
#define VEBAD       2      /* client was bad              */

#define PVERSION   1

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#ifdef UNIXLIKE
#include <unistd.h>
#else
typedef int pid_t;
unsigned sleep(unsigned seconds);
#endif

#include "../common/sock.h"      /* for Win32 or Unix */
#include "../common/sha256.h"    /* has word32, word16 */
#include "../common/wots/wots.h"
#define RPLISTLEN 32   /* for types.h */
#include "../common/types.h"     /* NODE, TX, el. al. */


/* for txbot.c */
typedef struct {
   byte addr[TXADDRLEN];
   byte balance[8];
   byte secret[32];
} TX_ADDR;

#define TX_ADDRLEN  (TXADDRLEN + 8 + 32)

typedef struct {
   byte addr[17];
   byte trancode[1];
   byte amount[5];
} TESTALIGN;


char *Statusarg;

char *show(char *state)
{
   char *cp, *sp;

   if(state == NULL) state = "(null)";
   if(Statusarg) strncpy(Statusarg, state, 8);
   return state;
}


word16 get16(void *buff)
{
   return *((word16 *) buff);
}

void put16(void *buff, word16 val)
{
   *((word16 *) buff) = val;
}

/* little-endian */
word32 get32(void *buff)
{
   return *((word32 *) buff);
}

void put32(void *buff, word32 val)
{
   *((word32 *) buff) = val;
}

/* buff<--val */
void put64(void *buff, void *val)
{
   ((word32 *) buff)[0] = ((word32 *) val)[0];
   ((word32 *) buff)[1] = ((word32 *) val)[1];
}


/* Compute *ap minus *bp giving *cp.  Result at *cp. */
int sub64(void *ap, void *bp, void *cp)
{
   byte *a, *b, *c;
   int j, t, carry = 0;

   a = ap; b = bp; c = cp;
   for(j = 0; j < 8; j++, a++, b++, c++) {
     t = *a - *b - carry;
     carry = (t >> 8) & 1;
     *c = t;
   }
   return carry;
}


/* Unsigned compare a to b.
 * Returns 0 if a==b, negative if a < b, or positive if a > b
 */
int cmp64(void *a, void *b)
{
   word32 *pa, *pb;

   pa = (word32 *) a;
   pb = (word32 *) b;
   if(pa[1] > pb[1]) return 1;
   if(pa[1] < pb[1]) return -1;
   if(pa[0] > pb[0]) return 1;
   if(pa[0] < pb[0]) return -1;
   return 0;
}


/* Network order word32 as byte a[4] to static alpha string like 127.0.0.1 */
char *ntoa(byte *a)
{
   static char s[24];

   sprintf(s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
   return s;
}

int exists(char *fname)
{
   FILE *fp;

   fp = fopen(fname, "rb");
   if(!fp) return 0;
   fclose(fp);
   return 1;
}

/* Default initial seed for rand16() */
static word32 Lseed = 1;

/* Seed the generator */
word32 srand16(word32 x)
{
   word32 r;

   r = Lseed;
   Lseed = x;
   return r;
}

/* High speed random number generator
 * Period: 2**32 randl4() -- returns 0-65535
 */
word32 rand16(void)
{
   Lseed = Lseed * 69069L + 262145L;
   return (Lseed >> 16);
}

#include "../common/crc16.c"

void crctx(TX *tx)
{
   put16(CRC_VAL_PTR(tx), crc16(CRC_BUFF(tx), CRC_COUNT));
}


/* bnum is little-endian on disk and core. */
char *bnum2hex(byte *bnum)
{
   static char buff[20];

   sprintf(buff, "%02x%02x%02x%02x%02x%02x%02x%02x",
                  bnum[7],bnum[6],bnum[5],bnum[4],
                  bnum[3],bnum[2],bnum[1],bnum[0]);
   return buff;
}


/* A less rigorous version for txbot without user input... */
void randombytes(byte *out, unsigned long outlen)
{
    static char state;
    static char buff[100];
    static char hash[32];
    int n;
    char c;
    FILE *fp;

    if(!state) {     /* on first call */
        put16(buff, rand16());
        put16(&buff[2], rand16());
        fp = fopen("/dev/random", "rb");
        if(fp) {
           for(n = 0; n < 100; n++) {
              if(fread(&c, 1, 1, fp) != 1) break;
              buff[n] ^= c;
           }
           fclose(fp);
        }
        state = 1;
    }  /* end if first call */
    for( ; outlen; ) {
       /* increment 800-bit number in buff */
       for(n = 0; n < 100; n++) {
          if(++buff[n] != 0) break;
       }       
       sha256((byte *) buff, 100, (byte *) hash);
       if(outlen < 32) n = outlen; else n = 32;
       memcpy(out, hash, n);
       out += n;
       outlen -= n;
   }
}  /* end randombytes() */



/*
 * Create an address that can be later signed with wots_sign():
 * It calls the function wots_pkgen() which creates the address.
*/

#define rndbytes(buff, len, seed) randombytes(buff, len)

/* Make up a random address that can be signed...
 * Outputs:
 *          addr[TXADDRLEN] takes the address (2208 bytes)
 *          secret[32]      needed for wots_sign()
 */
void create_addr(byte *addr, byte *secret, byte *seed)
{
   byte rnd2[32];

   rndbytes(secret, 32, seed);  /* needed later to use wots_sign() */

   rndbytes(addr, TXADDRLEN, seed);
   /* rnd2 is modified by wots_pkgen() */
   memcpy(rnd2, &addr[TXSIGLEN + 32], 32);
   /* generate a good addr */
   wots_pkgen(addr,              /* output first 2144 bytes */
              secret,            /* 32 */
              &addr[TXSIGLEN],   /* rnd1 32 */
              (word32 *) rnd2    /* rnd2 32 (modified) */
   );
   memcpy(&addr[TXSIGLEN+32], rnd2, 32);
}  /* end create_addr() */


/* Globals */
byte Needcleanup;    /* for Winsock */
word32 Port = 2095;  /* default server port */
word32 Peerip;       /* last peer connected */
unsigned Nextcore;   /* index into Coreplist for callserver() */
byte Cblocknum[8];   /* set from network */
byte Cbits;          /* remote capability bits */
byte Running = 1;
byte Sigint;
byte Trace;          /* output trace messages */
word32 Mfee[2] = { 500, 0 };  /* mining fee */
byte Zeros[8];

/* ip's of the Core Network */
word32 Coreplist[CORELISTLEN] = {
   0x0100007f,    /* local host */
   0x0b2a9741,    /* 65.151.42.11 */
   0x0c2a9741,
   0x0d2a9741,
   0x0e2a9741,
   0x0f2a9741,
   0x102a9741,
   0x112a9741,
   0x122a9741,
};


void ctrlc(int sig)
{
   signal(SIGINT, ctrlc);
   Sigint = 1;
   Running = 0;
}


/* shuffle a list of < 64k word32's */
void shuffle32(word32 *list, word32 len)
{
   word32 *ptr, *p2, temp;

   if(len < 2) return;
   for(ptr = &list[len - 1]; len > 1; len--, ptr--) {
      p2 = &list[rand16() % len];
      temp = *ptr;
      *ptr = *p2;
      *p2 = temp;
   }
}


/* Search an array list[] of word32's for a non-zero value.
 * A zero value marks the end of list (zero cannot be in the list).
 * Returns NULL if not found, else a pointer to value.
 */
word32 *search32(word32 val, word32 *list, unsigned len)
{
   for( ; len; len--, list++) {
      if(*list == 0) break;
      if(*list == val) return list;
   }
   return NULL;
}


int Exitcode = 1;

/* Display terminal error message
 * and exit.
 */
void fatal(char *fmt, ...)
{
   va_list argp;

   fprintf(stdout, "txbot: ");
   va_start(argp, fmt);
   vfprintf(stdout, fmt, argp);
   va_end(argp);
   printf("\n");
#ifdef _WINSOCKAPI_
   if(Needcleanup) WSACleanup();
#endif
   exit(Exitcode);
}


#ifdef FIONBIO
/* Set socket sd to non-blocking I/O on Win32 */
int nonblock(SOCKET sd)
{
   u_long arg = 1L;

   return ioctlsocket(sd, FIONBIO, (u_long FAR *) &arg);
}

int blocking(SOCKET sd)
{
   u_long arg = 0L;

   return ioctlsocket(sd, FIONBIO, (u_long FAR *) &arg);
}

#else
#include <fcntl.h>

/* Set socket sd to non-blocking I/O
 * Returns -1 on error.
 */
int nonblock(SOCKET sd)
{
   int flags;

   flags = fcntl(sd, F_GETFL, 0);
   return fcntl(sd, F_SETFL, flags | O_NONBLOCK);
}

/* Set socket sd to blocking I/O
 * Returns -1 on error.
 */
int blocking(SOCKET sd)
{
   int flags;

   flags = fcntl(sd, F_GETFL, 0);
   return fcntl(sd, F_SETFL, flags & (~O_NONBLOCK));
}

#endif


word32 str2ip(char *addrstr)
{
   struct hostent *host;
   struct sockaddr_in addr;

   if(addrstr == NULL) return 0;

   memset(&addr, 0, sizeof(addr));
   if(addrstr[0] < '0' || addrstr[0] > '9') {
      host = gethostbyname(addrstr);
      if(host == NULL) {
         printf("str2ip(): gethostbyname() failed\n");
         return 0;
      }
      memcpy((char *) &(addr.sin_addr.s_addr),
             host->h_addr_list[0], host->h_length);
   }
   else
      addr.sin_addr.s_addr = inet_addr(addrstr);

   return addr.sin_addr.s_addr;
}  /* end str2ip() */


/* Read-in the core ip list text file
 * each line:
 * 1.2.3.4  or
 * host.domain.name
 * Returns number of ip's put in list, else -1 on errors.
 */
int read_coreipl(char *fname)
{
   FILE *fp;
   char buff[128];
   int j;
   char *addrstr;
   word32 ip, *ipp;

   if(Trace) printf("Entering read_coreipl()\n");
   if(fname == NULL || *fname == '\0') return -1;
   fp = fopen(fname, "rb");
   if(fp == NULL) return -1;

   for(j = 0; j < CORELISTLEN; ) {
      if(fgets(buff, 128, fp) == NULL) break;
      if(*buff == '#') continue;
      addrstr = strtok(buff, " \r\n\t");
      if(Trace > 1) printf("   parse: %s", addrstr);  /* debug */
      if(addrstr == NULL) break;
      ip = str2ip(addrstr);
      if(!ip) continue;
      /* put ip in Coreplist[j] */
      Coreplist[j++] = ip;
      if(Trace) printf("Added %s to Coreplist\n", ntoa((byte *) &ip));
   }
   fclose(fp);
   return j;
}  /* end read_coreipl() */


/* Modified from connect2.c to use printf()
 * Returns: sd = a valid socket number on successful connect, 
 *          else INVALID_SOCKET (-1)
 */
SOCKET connectip(word32 ip)
{
   SOCKET sd;
   struct hostent *host;
   struct sockaddr_in addr;
   word16 port;
   time_t timeout;

   if((sd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
bad:
      printf("connectip(): cannot open socket.\n");
      return INVALID_SOCKET;
   }

   port = Port;
   memset((char *) &addr, 0, sizeof(addr));
   addr.sin_addr.s_addr = ip;
   addr.sin_family = AF_INET;  /* AF_UNIX */
   /* Convert short integer to network byte order */
   addr.sin_port = htons(port);

   if(Trace) {
      printf("Trying %s port %d...  ", ntoa((byte *) &ip), port);
   }

   nonblock(sd);
   timeout = time(NULL) + 3;

retry:
   if(connect(sd, (struct sockaddr *) &addr, sizeof(struct sockaddr))) {
#ifdef WIN32
      errno = WSAGetLastError();
#endif
      if(errno == EISCONN) goto out;
      if(time(NULL) < timeout && Sigint == 0) goto retry;
      closesocket(sd);
      if(Trace) printf("connectip(): cannot connect() socket.\n");
      return INVALID_SOCKET;
   }
   if(Trace) printf("connected.");
   nonblock(sd);
out:
   if(Trace) printf("\n");
   return sd;
}  /* end connectip() */


/* Send transaction in np->tx */
int sendtx2(NODE *np)
{
   int count;
   TX *tx;

   tx = &np->tx;

   put16(tx->version, PVERSION);
   put16(tx->network, TXNETWORK);
   put16(tx->trailer, TXEOT);
   put16(tx->id1, np->id1);
   put16(tx->id2, np->id2);
   crctx(tx);
   errno = 0;
   count = send(np->sd, TXBUFF(tx), TXBUFFLEN, 0);
   if(count != TXBUFFLEN) {
      if(Trace) printf("sendtx2() errno: %d\n", errno);
      return VERROR;
   }
   return VEOK;
}  /* end sendtx2() */


int send_op(NODE *np, int opcode)
{
   put16(np->tx.opcode, opcode);
   return sendtx2(np);
}


/* Receive next packet from NODE *np
 * Returns: VEOK=good, else error code.
 * Check id's if checkids is non-zero.
 * Set checkid to zero during handshake.
 */
int rx2(NODE *np, int checkids)
{
   int count, n;
   time_t timeout;
   TX *tx;

   tx = &np->tx;
   timeout = time(NULL) + 3;

   for(n = 0; ; ) {
      count = recv(np->sd, TXBUFF(tx) + n, TXBUFFLEN - n, 0);
      if(Sigint) return VERROR;
      if(count == 0) return VERROR;
      if(count < 0) {
         if(time(NULL) >= timeout) return -1;
         continue;
      }
      n += count;
      if(n == TXBUFFLEN) break;
   }  /* end for */

   /* check tx and return error codes or count */
   if(get16(tx->network) != TXNETWORK)
      return 2;
   if(get16(tx->trailer) != TXEOT)
      return 3;
   if(crc16(CRC_BUFF(tx), CRC_COUNT) != get16(tx->crc16))
      return 4;
   if(checkids && (np->id1 != get16(tx->id1) || np->id2 != get16(tx->id2)))
      return 5;
   return VEOK;
}  /* end rx2() */


/* Call peer and complete Three-Way */
int callserver(NODE *np, word32 ip)
{
   int ecode, j;

   memset(np, 0, sizeof(NODE));   /* clear node structure */
   np->sd = INVALID_SOCKET;
   np->sd = connectip(ip);
   if(np->sd == INVALID_SOCKET) return VERROR;
   np->src_ip = Peerip = ip;
   np->id1 = rand16();
   send_op(np, OP_HELLO);

   ecode = rx2(np, 0);
   if(ecode != VEOK) {
      if(Trace) printf("*** missing HELLO_ACK packet (%d)\n", ecode);
bad:
      closesocket(np->sd);
      np->sd = INVALID_SOCKET;
      return VERROR;
   }
   np->id2 = get16(np->tx.id2);
   np->opcode = get16(np->tx.opcode);
   if(np->opcode != OP_HELLO_ACK) {
      if(Trace) printf("*** HELLO_ACK is wrong: %d\n", np->opcode);
      goto bad;
   }
   put64(Cblocknum, np->tx.cblock);
   Cbits = np->tx.version[1];
   return VEOK;
}  /* end callserver() */


/* Set Cblocknum and Cbits from network.
 * Copy Cblocknum to a non-NULL bnum[].
 * Return VEOK on success, else VERROR.
 */
int set_bnum(byte *bnum)
{
   NODE node;

   if(callserver(&node, Peerip) != VEOK) return VERROR;
   if(bnum != NULL) memcpy(bnum, Cblocknum, 8);
   closesocket(node.sd);
   return VEOK;
}  /* end set_bnum() */


/* Returns VOEK on success, else VERROR.
 * opcode: OP_GETIPL, OP_TX, or OP_BALANCE.
 */
int send_tx(TX *tx, word32 ip, int opcode)
{
   NODE node;
   int status;

   if(callserver(&node, ip) != VEOK) return VERROR;
   memcpy(&node.tx, tx, sizeof(TX));
   put16(node.tx.len, 1);  /* signal server that we are a wallet */
   status = send_op(&node, opcode);
   if(opcode != OP_TX) {
      status = rx2(&node, 1);
      memcpy(tx, &node.tx, sizeof(TX));  /* return tx to caller's space */
   } 
   closesocket(node.sd);
   return status;
}  /* end send_tx() */


/* Get a peer list from a Mochimo peer in Coreplist[].
 * Return VEOK or VERROR.
 */
int get_ipl(void)
{
   TX tx;
   int status, j, k;
   unsigned len;
   word32 ip, *ipp;

   memset(&tx, 0, sizeof(TX));
   for(j = 0; j < CORELISTLEN && Sigint == 0; j++) {
      ip = Coreplist[j];
      if(ip == 0) continue;
      status = send_tx(&tx, ip, OP_GETIPL);
      len = get16(tx.len);
      /*
       * Copy the peer list to Coreplist[]
       */
      if(status == VEOK && len <= TRANLEN) {
         ipp = (word32 *) TRANBUFF(&tx);
         shuffle32(ipp, CORELISTLEN);
         for(k = 0; k < CORELISTLEN && len > 0; ipp++, len -= 4) {
                if(*ipp == 0) continue;
                if(search32(*ipp, Coreplist, k)) continue;
                Coreplist[k++] = *ipp;
                if(Trace) printf("Added %s\n", ntoa((byte *) ipp));
         }
         if(k) {
            if(Trace) printf("Addresses added: %d\n", k);
         }
         return VEOK;
      }  /* end if copy ip list */
   }  /* end for try again */
   return VERROR;
}  /* end get_ipl() */


void usage(void)
{
   printf("\nUsage: txbot [-option -option2 . . .] addrfile\n"
      "options:\n"
      "           -aS set address string to S\n"
      "           -pN set TCP port to N\n"
      "           -cS read core ip list from file S\n"
      "           -r  refresh core ip list from network\n"
      "           -tN set Trace to N\n"
      "           -D  daemon (ignore all signals but SIGTERM)\n"
      "           -xxxxxxx replace xxxxxxx with state\n"
      "           -h  this message\n"
   );
   exit(1);
}


void restart(char *mess)
{
   Exitcode = 2;
   fatal(mess);
}


int main(int argc, char **argv)
{
   static int j, pass, status, fails, idx;
   static byte daemonise, getlist;
   static char *addrfile, *peeraddr, *corefname;
   static FILE *fp;
   TX tx;
   TX_ADDR addr;
   word32 coresave[CORELISTLEN]; 
   byte message[32], rnd2[32], secret[32];  /* for WOTS signature */
   byte seed[64];
   byte dsecret[32], csecret[32];
   byte s[8], d[8], c[8];

#ifdef _WINSOCKAPI_
   static WORD wsaVerReq;
   static WSADATA wsaData;

   wsaVerReq = 0x0101;	/* version 1.1 */
   if(WSAStartup(wsaVerReq, &wsaData) == SOCKET_ERROR)
      fatal("WSAStartup()");
   Needcleanup = 1;
#endif

   if(sizeof(TX_ADDR) != TX_ADDRLEN || sizeof(TESTALIGN) != 23)
      fatal("struct size error.\nSet compiler options for byte alignment.");

   if(argc < 2) usage();
   for(j = 1; j < argc; j++) {
      if(argv[j][0] != '-') break;
      switch(argv[j][1]) {
         case 'D':  daemonise = 1;
                    break;
         case 'r':  getlist = 1;
                    break;
         case 'p':  Port = atoi(&argv[j][2]);   /* TCP port */
                    break;
         case 'a':  if(argv[j][2]) peeraddr = &argv[j][2];
                    break;
         case 'c':  corefname = &argv[j][2];   /* block-server network */
                    if(!exists(corefname)) fatal("Cannot find %s", corefname);
                    break;
         case 't':  Trace = atoi(&argv[j][2]); /* set trace level  */
                    break;
         case 'x':  if(strlen(argv[j]) != 8) break;
                    Statusarg = argv[j];
                    break;
         default:   usage();
      }  /* end switch */
   }  /* end for j */

   addrfile = argv[j];
   if(addrfile == NULL) fatal("missing TX file");
   /* Open input address file */
   fp = fopen(addrfile, "r+b");
   if(fp == NULL) fatal("cannot open %s", addrfile);

   srand16(time(NULL));

   printf("\nMochimo -- TxBot -- version 1.0\n"
          "Copyright (c) 2018 by Adequate Systems, LLC."
          "  All Rights Reserved.\n\n");
   /*
    * Ignore all signals.
    */
   for(j = 0; j <= NSIG; j++) signal(j, SIG_IGN);
   if(!daemonise) signal(SIGINT, ctrlc);  /* set Running = 0 on ctrl-c */
   signal(SIGTERM, ctrlc);
   memcpy(coresave, Coreplist, CORELISTLEN);
   pass = 0;

readcore:
   if(corefname) {
      memset(Coreplist, 0, sizeof(Coreplist));
      j = read_coreipl(corefname);
      if(Trace) printf("read_coreipl() returned %d\n", j);
   }
   else {
      memcpy(Coreplist, coresave, CORELISTLEN);
      for(j = 0; j < CORELISTLEN && Coreplist[j]; ) j++;
   }
   shuffle32(Coreplist, j);
   if(peeraddr) Coreplist[0] = str2ip(peeraddr);
   if(Coreplist[0] == 0) fatal("Coreplist[0] is zero");
   Nextcore = 0;
   if(fseek(fp, 0, SEEK_END) || ftell(fp) < TX_ADDRLEN)
      fatal("%s < %d bytes", addrfile, TX_ADDRLEN);  /* should not happen */
   idx = 0;  /* address index from end of file fp */
   if(Trace)
      printf("Addresses in file: %d\n", (int) (ftell(fp) / TXADDRLEN));

   /* Main Loop -- Begin sending TX's */
   for( ; Running; Nextcore++) {
      show("main");
      if(Nextcore >= CORELISTLEN) Nextcore = 0;
      if(Coreplist[Nextcore] == 0) Nextcore = 0;
      if(pass > MAXLOOPS) restart("restart -- MAXLOOPS");
      if(fails >= MAXFAILS) {
         if(Trace) printf("pass %d, fetching ip list...\n", pass);
         show("get_ipl");
         fails = 0;
         if(get_ipl() != VEOK) goto readcore;
         Nextcore = -1;
         continue;
      }
      /* back file up one address */
      idx--;
      if(Trace) printf("pass %d, back up to addr[%d]...\n", pass, idx);
      if(ftell(fp) < TX_ADDRLEN || fseek(fp, -(TX_ADDRLEN), SEEK_CUR)) {
         if(Trace) printf("seek end.  Loop list...\n");
         fseek(fp, 0, SEEK_END);
         idx = 0;
         continue;
      }
      if(fread(&addr, 1, sizeof(addr), fp) != sizeof(addr)) {
badio:
          fatal("I/O error");
      }
      /* re-que file */
      if(fseek(fp, -(TX_ADDRLEN), SEEK_CUR)) goto badio;
      pass++;

      /* query balance of addr.addr */
      show("query");
      memset(&tx, 0, sizeof(tx));
      put16(tx.len, 1);  /* signal that we are a wallet */
      memcpy(tx.src_addr, addr.addr, TXADDRLEN);  /* set addr to query */
      status = send_tx(&tx, Coreplist[Nextcore], OP_BALANCE);
      if(status != VEOK) { fails++; continue; }
      if(cmp64(tx.send_total, Zeros) == 0) continue;
      put64(s, tx.send_total);  /* amount in addr */

      /* set-up transaction to send */
      show("send_tx");
      memset(&tx, 0, sizeof(tx));
      memcpy(tx.src_addr, addr.addr, TXADDRLEN);
      create_addr(tx.dst_addr, dsecret, seed);
      create_addr(tx.chg_addr, csecret, seed);
      put64(d, Zeros);
      d[0] = 1;  /* dst amount = 1 Satoshi */
      sub64(s, d, c);
      sub64(c, Mfee, c);
      put64(tx.send_total, d);
      put64(tx.change_total, c);
      put64(tx.tx_fee, Mfee);

      /* compute message hash */
      sha256(tx.src_addr, SIG_HASH_COUNT, message);

      /* sign TX with secret key for src_addr */
      memcpy(rnd2, &tx.src_addr[TXSIGLEN+32], 32); /* for wots_sign() */
      wots_sign(tx.tx_sig,    /* output 2144 */
                message,      /* hash 32 */
                addr.secret,  /* random secret key 32 */
                &tx.src_addr[TXSIGLEN],  /* rnd1 32 */
                (word32 *) rnd2          /* rnd2 32 (maybe modified) */
      );

      status = send_tx(&tx, Coreplist[Nextcore], OP_TX);
      if(status != VEOK) fails++;
      if(fseek(fp, 0, SEEK_END)) goto badio;
      if(fwrite(tx.chg_addr, 1, TXADDRLEN, fp) != TXADDRLEN) goto badio;
      if(fwrite(Zeros, 1, 8, fp) != 8) goto badio;
      if(fwrite(csecret, 1, 32, fp) != 32) goto badio;
   }  /* end for Running */

#ifdef _WINSOCKAPI_
    if(Needcleanup) WSACleanup();
#endif

   return 0;
}  /* end main() */
