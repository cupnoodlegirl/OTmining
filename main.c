#include <assert.h>
#include <inttypes.h>
#include <stdint.h>

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <blkmaker.h>
#include <blkmaker_jansson.h>
#include <curl/curl.h>
#include <gcrypt.h>

// convert to little endian
#define REV(X)                                                                 \
  ((X << 24) | (((X >> 16) << 24) >> 16) | (((X << 16) >> 24) << 16) |         \
   (X >> 24))

struct Env {
  char *user;
  char *password;
  char *ip;
  char *port;
};

struct Buffer {
  char *data;
  int data_size;
};

size_t buffer_writer(char *ptr, size_t size, size_t nmemb, void *stream) {
  struct Buffer *buf = (struct Buffer *)stream;
  int block = size * nmemb;
  if (!buf) {
    return block;
  }

  if (!buf->data) {
    buf->data = (char *)malloc(block);
  } else {
    buf->data = (char *)realloc(buf->data, buf->data_size + block);
  }

  if (buf->data) {
    memcpy(buf->data + buf->data_size, ptr, block);
    buf->data_size += block;
  }

  return block;
}

static void dump_json(json_t *req) {
  char *s = json_dumps(req, JSON_INDENT(2));
  puts(s);
  free(s);
}

static bool my_sha256(void *digest, const void *buffer, size_t length) {
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, buffer, length);
  return true;
}

void getblocktemplate(CURL *curl, struct Buffer *buf, struct Env *env) {
  if (!curl) {
    buf->data = NULL;
    buf->data_size = 0;
    return;
  }
  struct curl_slist *headers = NULL;

  const char *data = "{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
                     "\"method\": \"getblocktemplate\", \"params\": [] }";

  headers = curl_slist_append(headers, "content-type: text/plain;");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  char *url = (char *)malloc(strlen("http://") + strlen(env->ip) + strlen(":") +
                             strlen(env->port) + strlen("/") + 1);
  memcpy(url, "http://", strlen("http://"));
  memcpy(url + strlen("http://"), env->ip, strlen(env->ip));
  memcpy(url + strlen("http://") + strlen(env->ip), ":", strlen(":"));
  memcpy(url + strlen("http://") + strlen(env->ip) + strlen(":"), env->port,
         strlen(env->port));
  memcpy(url + strlen("http://") + strlen(env->ip) + strlen(":") +
             strlen(env->port),
         "/", strlen("/") + 1);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, buf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, buffer_writer);

  const char *colon = ":";
  char *userpwd = (char *)malloc(strlen(env->user) + strlen(env->password) +
                                 strlen(colon) + 1);
  memcpy(userpwd, env->user, strlen(env->user));
  memcpy(userpwd + strlen(env->user), colon, strlen(colon));
  memcpy(userpwd + strlen(env->user) + strlen(colon), env->password,
         strlen(env->password) + 1);
  curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);

  curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

  curl_easy_perform(curl);

  strtok(buf->data, "\n");
}

void submitblock(CURL *curl, const char *blockhex, struct Env *env) {
  char *part1 = "{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
                "\"method\": \"submitblock\", \"params\":[\"";
  char *part2 = "\"]}";
  char *data1 =
      (char *)malloc(strlen(part1) + strlen(part2) + strlen(blockhex) + 1);
  memcpy(data1, part1, strlen(part1));
  memcpy(data1 + strlen(part1), blockhex, strlen(blockhex));
  memcpy(data1 + strlen(part1) + strlen(blockhex), part2, strlen(part2) + 1);
  printf("%s\n", data1);
  printf("%ld\n", (long)strlen(data1));
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "content-type: text/plain;");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  char *url = (char *)malloc(strlen("http://") + strlen(env->ip) + strlen(":") +
                             strlen(env->port) + strlen("/") + 1);
  memcpy(url, "http://", strlen("http://"));
  memcpy(url + strlen("http://"), env->ip, strlen(env->ip));
  memcpy(url + strlen("http://") + strlen(env->ip), ":", strlen(":"));
  memcpy(url + strlen("http://") + strlen(env->ip) + strlen(":"), env->port,
         strlen(env->port));
  memcpy(url + strlen("http://") + strlen(env->ip) + strlen(":") +
             strlen(env->port),
         "/", strlen("/") + 1);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data1));
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data1);

  char *userpwd = (char *)malloc(strlen(env->user) + strlen(env->password) +
                                 strlen(":") + 1);
  memcpy(userpwd, env->user, strlen(env->user));
  memcpy(userpwd + strlen(env->user), ":", strlen(":"));
  memcpy(userpwd + strlen(env->user) + strlen(":"), env->password,
         strlen(env->password) + 1);
  curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);

  curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

  curl_easy_perform(curl);

  free(data1);
}

void create_coinbase(char *str) {
  int version = 2;
  int incnt = 1;
  const char *prev_hash =
      "0000000000000000000000000000000000000000000000000000000000000000";
  // prev out n, index of the output
  const char *prev_out = "ffffffff";
  int cbscriptSiglen = 19;
  /* from version 2, height value is required in scriptSig (BIP34)
   number of bytes at first 1 byte -> 0x01
   following bytes are little-endian representation of the
   number -> 0x67 */
  // coinbase script
  const char *cbsigScript = "016e006700456c6967697573005047dc66085f";
  const char *sequence = "ffffffff";
  int outcnt = 1;
  // tx out #1 amount // 16|1|16^3|16^2 byte order due to endian?
  const char *outamount = "00f2052a01000000";
  int outscriptlen = 25;
  // tx out #1
  const char *outscript = "76a9144ebeb1cd26d6227635828d60d3e0ed7d0da248fb88ac";
  // lock time
  const char *locktime = "00000000";
  snprintf(str, 256 * sizeof(char), "%08x%02x%s%s%02x%s%s%02x%s%02x%s%s",
           REV(version), incnt, prev_hash, prev_out, cbscriptSiglen,
           cbsigScript, sequence, outcnt, outamount, outscriptlen, outscript,
           locktime);
}

int main(int argc, char **argv) {
  /* command line option */
  int opt;
  struct Env *env;
  env = (struct Env *)malloc(sizeof(*env));
  env->user = NULL;
  env->password = NULL;
  env->ip = NULL;
  env->port = NULL;
  while ((opt = getopt(argc, argv, "u:p:i:r:")) != -1) {
    switch (opt) {
    case 'u': // USER
      env->user = (char *)malloc(strlen(optarg));
      env->user = optarg;
      break;
    case 'p': // PASSWORD
      env->password = (char *)malloc(strlen(optarg));
      env->password = optarg;
      break;
    case 'i': // IP
      env->ip = (char *)malloc(strlen(optarg));
      env->ip = optarg;
      break;
    case 'r': // RPCPORT
      env->port = (char *)malloc(strlen(optarg));
      env->port = optarg;
      break;
    default:
      fprintf(stderr,
              "Usage: %s -u <user> -p <password> -i <ip> -r <rpcport>\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (env->user == NULL || env->password == NULL || env->ip == NULL ||
      env->port == NULL) {
    fprintf(stderr, "Usage: %s -u <user> -p <password> -i <ip> -r <rpcport>\n",
            argv[0]);
    exit(EXIT_FAILURE);
  }
  /* curl and response buffer initialization */
  CURL *curl = curl_easy_init();

  struct Buffer *buf;
  buf = (struct Buffer *)malloc(sizeof(struct Buffer));
  buf->data = NULL;
  buf->data_size = 0;

  /* getblocktemplate request */
  getblocktemplate(curl, buf, env);

  /* create block for mining from block template */
  blktemplate_t *tmpl;
  json_t *req;
  json_error_t jsone;
  const char *err;

  blkmk_sha256_impl = my_sha256;

  tmpl = blktmpl_create();
  assert(tmpl);
  // req = blktmpl_request_jansson(blktmpl_addcaps(tmpl), NULL);
  // assert(req);

  // send req to server and parse response into req
  // dump_json(req);
  // json_decref(req);

  req = json_loads(buf->data, 0, &jsone);
  dump_json(req);

  assert(req);

  char *cbstr = (char *)malloc(256 * sizeof(char));
  create_coinbase(cbstr);
  printf("%s\n", cbstr);
  json_t *cbreq = json_pack("{s:s}", "data", cbstr);
  dump_json(cbreq);

  json_t *partreq;
  partreq = json_object_get(req, "result");

  json_object_set(partreq, "coinbasetxn", cbreq);

  json_object_set(req, "result", partreq);
  dump_json(req);

  err = blktmpl_add_jansson(tmpl, req, time(NULL));
  json_decref(req);
  if (err) {
    fprintf(stderr, "Error adding block template: %s", err);
    assert(0 && "Error adding block template");
  }
  /* solve */
  while (blkmk_time_left(tmpl, time(NULL)) && blkmk_work_left(tmpl)) {
    unsigned char data[80], hash[32];
    size_t datasz;
    unsigned int dataid;
    uint32_t nonce;

    datasz =
        blkmk_get_data(tmpl, data, sizeof(data), time(NULL), NULL, &dataid);
    assert(datasz >= 76 && datasz <= sizeof(data));

    // mine the right nonce
    // this is iterating in native order, even though SHA256 is big endian,
    // because we don't implement noncerange
    // however, the nonce is always interpreted as big endian, so we need to
    // convert it as if it were big endian
    for (nonce = 0; nonce < 0xffffffff; ++nonce) {
      *(uint32_t *)(&data[76]) = nonce;
      assert(my_sha256(hash, data, 80));
      assert(my_sha256(hash, hash, 32));
      if (!*(uint32_t *)(&hash[29]))
        break;
      if (!(nonce % 0x1000)) {
        printf("0x%8" PRIx32 " hashes done...\r", nonce);
        fflush(stdout);
      }
    }
    printf("Found nonce: 0x%8" PRIx32 " \n", nonce);
    nonce = ntohl(nonce);

    req = blkmk_submit_jansson(tmpl, data, dataid, nonce);
    assert(req);
    // send req to server
    dump_json(req);
  }
  /* submitblock request */
  const char *blockhex =
      json_string_value(json_array_get(json_object_get(req, "params"), 0));
  submitblock(curl, blockhex, env);

  curl_easy_cleanup(curl);
  blktmpl_free(tmpl);
  return 0;
}
