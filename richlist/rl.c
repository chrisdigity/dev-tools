


#include "../common/config.h"
#include "../common/mochimo.h"
#include "../common/add64.c"
#include "../common/rand.c"

#ifdef UNIXLIKE
#include <unistd.h>
#define CLEARSCR() system("clear")
#else
#define CLEARSCR() clrscr()
void clrscr(void);
typedef int pid_t;
#endif

/* Globals */
int listlen;
word32 Bnum;
FILE *Bfp;
word32 Hdrlen;
byte Maddr[TXADDRLEN];
byte Sigint;
word32 Txidx;
long Foffset;

void ctrlc(int sig)
{
   signal(SIGINT, ctrlc);
   Sigint = 1;
}


/* byte buffer access
 * little-endian compiler order
 */

word16 get16(void *buff)
{
   return *((word16 *) buff);
}

void put16(void *buff, word16 val)
{
   *((word16 *) buff) = val;
}

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


/* Prototypes */
char *trigg_check(byte *in, byte d, byte *bnum);


/* Find a binary string, s, of length, len, in file fp.
 * Caller sets seek position of fp before call.
 * If found, return offset of start of match, else return -1.
 */
long findtag(byte *s, int len, FILE *fp)
{
   byte *cp, c;
   int len2;

   for(cp = s, len2 = len; len2; ) {
      if(fread(&c, 1, 1, fp) != 1) return -1L;
      if(*cp != c) {
         cp = s;
         len2 = len;
         if(*cp == c) { cp++; len2--; }
         continue;
      }
      len2--;
      cp++;
   }
   return ftell(fp) - len;
}


/* Convert a hex ASCII string hex into a value. */
unsigned long htoul(char *hex)
{
   static char hextab[] = "0123456789abcdef";
   char *cp;
   unsigned long val;

   val = 0;
   for( ; *hex; hex++) {
      if(*hex == 'x' || *hex == 'X') continue;
      cp = strchr(hextab, tolower(*hex));
      if(!cp) break;
      val = (val * 16) + (cp - hextab);
   }
   return val;
}  /* end htoul() */


/* Convert ASCII string s into a value.
 * 0123 or 0x123 is hex, otherwise, s is decimal.
 */
unsigned long getval(char *s)
{
   if(s == NULL) return 0;
   while(*s && *s <= ' ') s++;
   if(*s == '\0') return 0;
   /* if(strchr(s, '.')) value is float */
   if(*s == '0') return htoul(s);
   return strtoul(s, NULL, 10);  /* for really big unsigned longs */
/*   return atol(s); */
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


char *b2hex8(byte *amt)
{
   static char str[20];

   sprintf(str, "%02x%02x%02x%02x%02x%02x%02x%02x",
           amt[0], amt[1], amt[2], amt[3],
           amt[4], amt[5], amt[6], amt[7]);
   return str;
}


void b2hexch(byte *addr, int len, int lastchar)
{
   int n;

   for(n = 0; len; len--) {
      printf("%02x", *addr++);
      if(++n >= 36) {
         printf("\n");
         n = 0;
      }
   }
   if(lastchar)
      printf("%c", lastchar);
}

#define bytes2hex(addr, len) b2hexch(addr, len, '\n')

/* Seek to end of fname and read block trailer.
 * Return 0 on success, else error code.
 * fp is open and stays open.
 */
int readtrailer2(BTRAILER *trailer, FILE *fp)
{

   if(fseek(fp, -(sizeof(BTRAILER)), SEEK_END) != 0) {
bad:
      printf("Cannot read block trailer\n");
      return 1;
   }
   if(fread(trailer, 1, sizeof(BTRAILER), fp) != sizeof(BTRAILER))
      goto bad;
   return 0;
}


/* Return 0 on success.
 * Non-NULL filename over-rides bnum.
 */
int read_block(word32 bnum, BHEADER *bh, BTRAILER *bt, char *filename)
{
   char fnamebuff[100], *fname;
   int count;
   static byte bnum8[8];

   if(Bfp) fclose(Bfp);
   if(filename) fname = filename;
   else {
      fname = fnamebuff;
      put32(bnum8, bnum);
      sprintf(fname, "b%s.bc", bnum2hex(bnum8));
   }
   Bfp = fopen(fname, "rb");
   if(Bfp == NULL) {
      printf("Cannot open %s\n", fname);
      return 1;
   }
   Bnum = bnum;
   count = fread(&Hdrlen, 1, 4, Bfp);
   if(count != 4) {
err:
      printf("Error reading %s\n", fname);
      fclose(Bfp);
      Bfp = NULL;
      return 2;
   }
   memset(bh, 0, sizeof(BHEADER));
   put32(bh->hdrlen, Hdrlen);
   if(Hdrlen == sizeof(BHEADER) && Bnum != 0) {
      fseek(Bfp, 0, SEEK_SET);
      if(fread(bh, 1, sizeof(BHEADER), Bfp) != sizeof(BHEADER))
         goto err;
   }
   if(Bnum == 0) printf("%s is the Genesis Block.\n\n", fname);
   else {
      if((Bnum & 255) == 0)
         printf("%s is a neo-genesis block with %d ledger entries.\n\n",
                fname, (int) ((get32(bh->hdrlen) - 4) / sizeof(LENTRY)));
   }

   if(readtrailer2(bt, Bfp) != 0) goto err;
   return 0;  /* success */
}  /* end read_block() */


/* Convert nul-terminated hex string in[] to binary out[].
 * in and out may point to same space.
 * example: in[]   = { '0', '1', 'a', '0' }
 *          out[]: = { 1, 160 }
*/
int hex2bytes(char *in, char *out)
{
   char *hp;
   static char hextab[] = "0123456789abcdef";
   int j, len, val = 0;

   len = strlen(in);
   if(len & 1) return 0;  /* len should be even */
   for(j = 0; *in && len; in++, j++, len--) {
      hp = strchr(hextab, tolower(*in));
      if(!hp) break;  /* if non-hex */
      val = (val * 16) + (hp - hextab);  /* convert 4 bits per char */
      if(j & 1) *out++ = val;  /* done with this byte */
   }
   return j;  /* number of characters scanned */
}


#define I_ZSUP 1   /* zero suppress */

/* Format an 8-byte value into out for display. */
char *itoa64(void *val64, char *out, int dec, int flags)
{
   int count;
   static char s[24];
   char *cp, zflag = 1;
   word32 *tab;
   byte val[8];

   /* 64-bit little-endian */
   static word32 table[] = {
     0x89e80000, 0x8ac72304,      /* 1e19 */
     0xA7640000, 0x0DE0B6B3,      /* 1e18 */
     0x5D8A0000, 0x01634578,      /* 1e17 */
     0x6FC10000, 0x002386F2,      /* 1e16 */
     0xA4C68000, 0x00038D7E,      /* 1e15 */
     0x107A4000, 0x00005AF3,      /* 1e14 */
     0x4E72A000, 0x00000918,      /* 1e13 */
     0xD4A51000, 0x000000E8,      /* 1e12 */
     0x4876E800, 0x00000017,      /* 1e11 */
     0x540BE400, 0x00000002,      /* 1e10 */
     0x3B9ACA00, 0x00000000,      /* 1e09 */
     0x05F5E100, 0x00000000,      /* 1e08 */
     0x00989680, 0x00000000,      /* 1e07 */
     0x000F4240, 0x00000000,      /* 1e06 */
     0x000186A0, 0x00000000,      /* 1e05 */
     0x00002710, 0x00000000,      /* 1e04 */
     0x000003E8, 0x00000000,      /* 1e03 */
     0x00000064, 0x00000000,      /* 1e02 */
     0x0000000A, 0x00000000,      /* 1e01 */
     0x00000001, 0x00000000,      /*   1  */
   };

   if(out == NULL) cp = s; else cp = out;
   out = cp;  /* return value */
   if((flags & I_ZSUP) == 0) zflag = 0;  /* leading zero suppression flag */
   dec = 20 - (dec + 1);  /* where to put decimal point */
   put64(val, val64);

   for(tab = table; ; ) {
      count = 0;
      for(;;) {
         count++;
         if(sub64(val, tab, val) != 0) {
            count--;
            add64(val, tab, val);
            *cp = count + '0';
            if(*cp == '0' && zflag) *cp = ' '; else zflag = 0;
            cp++;
            if(dec-- == 0) *cp++ = '.';
            tab += 2;
            if(tab[0] == 1 && tab[1] == 0) {
               *cp = val[0] + '0';
               return out;
            }
            break;
         }
      }  /* end for */
   }  /* end for */
}  /* end itoa64() */


/* Left justify */
char *itoa64lj(void *val64, char *out, int dec, int flags)
{
   char *cp;

   cp = itoa64(val64, out, dec, flags);
   while(*cp && (*cp == ' ' || *cp == '.')) cp++;
   return cp;
}


/* Input a string to buff from stdin.
 * len > 2
 */
char *tgets(char *buff, int len)
{
   char *cp, fluff[16];

   *buff = '\0';
   fgets(buff, len, stdin);
   cp = strchr(buff, '\n');
   if(cp) *cp = '\0';
   else {
      for(;;) {
         if(fgets(fluff, 16, stdin) == NULL) break;
         if(strchr(fluff, '\n') != NULL) break;
      }
   }
   return buff;
}


void banner(void) {printf("The Mochi Rich List version 0.1a\n\n");}


char *timestr(word32 timeval)
{
  time_t t;
  static char out[32];
  char *cp;

  t = timeval;
  strcpy(out, asctime(gmtime(&t)));
  cp = strchr(out, '\n');
  if(cp) strcpy(cp, " GMT");
  return out;
}


/* Hex converter */
void hexcon(void)
{
   char buff[81];
   unsigned long val;

   for(;;) {
      printf("Enter value (e.g. decimal 123, or hex 0123, p=previous): ");
      tgets(buff, 80);
      if(buff[0] < '0' || buff[0] > '9') break;
      val = getval(buff);
      printf("%lu  (0x%lx)  [0x%s]\n", val, val, b2hex8((byte *) &val));
   }  /* end for */
}

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

/* Ledger explorer.
 * fp is open.
 * top = 0 means ledger.dat type files.
 * top = 4 means Genesis or NG blocks.
 * Returns error code or zero.
 */
int lx(FILE *fp, word32 top)
{
   long offset, saveoff, temp, lastfind;
   LENTRY le;
   int count;
   char buff[81];
   static char sbuff[81];
   int len = 2;
   word32 idx, j;
   unsigned long flen;

   if(fp == NULL) return 1;

   if(top == 4) {
      if(Bnum == 0) printf("Genesis Block ");
      else printf("neo-genesis block ");
   }

   fseek(fp, 0, SEEK_END);
   flen = ftell(fp);
   fseek(fp, top, SEEK_SET);
   lastfind = 0;

   printf("Populating Ledger Entries...\n");
   byte richlist[listlen][TXADDRLEN];
   byte richbal[listlen][TXAMOUNT];
   for(idx = 0; ; ) {
      count = fread(&le, 1, sizeof(LENTRY), fp);
      if(count != sizeof(LENTRY)) {memset(&le, 0, sizeof(LENTRY));break;}
      for(j=0; j<listlen; j++) {
         byte a[8], b[8];
         int c, d;
         for (c = 7, d = 0; c >= 0; c--, d++) {
            a[d] = le.balance[c];
            b[d] = richbal[j][c];
         }
         int compare = memcmp(a,b,sizeof(le.balance));
         if(compare > 0) {
            for(int k = listlen-1; k>j; k--) {
               memcpy(richlist[k],richlist[k-1],sizeof(le.addr));
               memcpy(richbal[k],richbal[k-1],sizeof(le.balance));
            }
            memcpy(richlist[j],le.addr,sizeof(le.addr));
            memcpy(richbal[j],le.balance,sizeof(le.balance));
            break;
         }
      }
      idx++;
   }  /* end for */
   printf("%u Entries found...\n",idx);
   word32 idxlen = idx;
   printf("Display Rich List...\n");
   for(idx=0; idx<listlen;idx++) {
      //printf("%u | %s | 0x", idx, itoa64lj(richbal[idx], NULL, 9, 1));
      printf("%03u | %s | 0x", idx+1, itoa64lj(richbal[idx], NULL, 9, 1));
      bytes2hex(richlist[idx], 16);
   }

   return 0;
err:
   printf("ERROR: Something broke...\n");
   return 0;
}  /* end lx() */


/* Explore a ledger.dat type file, lfile. */
int showledger(char *lfile)
{
   FILE *fp;
   int status;

   fp = fopen(lfile, "rb");
   if(!fp) {
      printf("Cannot open %s\n", lfile);
      return 1;
   }
   Bnum = 2;  /* not an NG block */
   status = lx(fp, 0);
   fclose(fp);
   return status;
}

void usage(void) {printf("\nUsage: rl [ledger file] [length of richlist]\n");exit(1);}

int main(int argc, char **argv)
{
   printf("\n");
   banner();
   if(argc > 2) listlen = atoi(&argv[2][0]);
   else listlen = 10;
   if(argc > 1) {
      exit(showledger(argv[1]));
   } else usage();
}  /* end main() */
