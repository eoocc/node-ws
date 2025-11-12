const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口                
const DOMAIN = process.env.DOMAIN || 'xx-hf.space.domain'; // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || 'Hug';                    // 节点名称
const PORT = process.env.PORT || 7860;                     // http和ws服务端口

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://speed.cloudflare.com/meta');
    const data = res.data;
    ISP = `${data.country}-${data.asOrganization}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();
const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, 'utf8', (err, content) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(content);
        });
        return;
  } else if (req.url === `/${SUB_PATH}`) {
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;  // 使用UUID而不是TROJAN_PASSWORD
    const combinedContent = `${vlessURL}\n${trojanURL}`;
    const base64Content = Buffer.from(combinedContent).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocket.Server({ server: httpServer });
const uuid = UUID.replace(/-/g, "");
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
// Custom DNS resolver function
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }

    let attempts = 0;
    
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: {
          'Accept': 'application/dns-json'
        }
      })
      .then(response => {
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(record => record.type === 1);
          if (ip) {
            resolve(ip.data);
            return;
          }
        }
        tryNextDNS();
      })
      .catch(error => {
        // console.warn(`DNS resolution failed with ${dnsServer}:`, error.message);
        tryNextDNS();
      });
    }
    
    tryNextDNS();
  });
}

wss.on('connection', ws => {
  // console.log("Connected successfully");
  ws.once('message', msg => {
    if (msg.length >= 58 && msg[56] === 0x0d && msg[57] === 0x0a) {
      handleTrojanProtocol(ws, msg).catch(error => {
        console.error('Error handling Trojan protocol:', error);
        ws.close();
      });
    } else {
      const [VERSION] = msg;
      const id = msg.slice(1, 17);
      if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return;
      let i = msg.slice(17, 18).readUInt8() + 19;
      const port = msg.slice(i, i += 2).readUInt16BE(0);
      const ATYP = msg.slice(i, i += 1).readUInt8();
      const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
      (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
      // console.log(`Connection from ${host}:${port}`);
      ws.send(new Uint8Array([VERSION, 0]));
      const duplex = createWebSocketStream(ws);
      resolveHost(host)
        .then(resolvedIP => {
          // console.log(`Resolved ${host} to ${resolvedIP} using custom DNS`);
          net.connect({ host: resolvedIP, port }, function() {
            this.write(msg.slice(i));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          }).on('error', (error) => {
            console.error(`Connection error to ${resolvedIP}:${port}`, error.message);
          });
        })
        .catch(error => {
          console.error(`DNS resolution failed for ${host}:`, error.message);
          net.connect({ host, port }, function() {
            this.write(msg.slice(i));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          }).on('error', (error) => {
            console.error(`Connection error to ${host}:${port}`, error.message);
          });
        });
    }
  }).on('error', () => {});
});

// SHA-224 implementation for Trojan
async function sha224(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const msgLen = data.length;
  const bitLen = msgLen * 8;
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen, false);
  for (let chunk = 0; chunk < paddedLen; chunk += 64) {
    const W = new Uint32Array(64);
    
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(chunk + i * 4, false);
    }
    
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    
    let [a, b, c, d, e, f, g, h] = H;
    
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  
  const result = [];
  for (let i = 0; i < 7; i++) {  // SHA-224 uses only the first 7 words (28 bytes)
    result.push(
      ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
      (H[i] & 0xff).toString(16).padStart(2, '0')
    );
  }
  return result.join('').substring(0, 56);  // 确保只返回56个字符（28字节的十六进制表示）
}

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

async function handleTrojanProtocol(ws, msg) {
  const receivedHashHex = msg.slice(0, 56).toString();  // 获取客户端发送的十六进制字符串
  const expectedHashHex = await sha224(UUID);  // 获取我们计算的十六进制哈希
  
  // 添加调试日志
  console.log('Trojan password verification:');
  console.log('  UUID:', UUID);
  console.log('  Expected hash (hex):', expectedHashHex);
  console.log('  Received hash (hex):', receivedHashHex);
  console.log('  Hashes match:', receivedHashHex === expectedHashHex);
  
  if (receivedHashHex !== expectedHashHex) {  // 直接比较十六进制字符串
    console.error('Trojan password mismatch');
    ws.close();
    return false;
  }
  
  let i = 58; // 56 (hash) + 2 (CRLF)
  console.log('Parsing command and address info from index:', i);
  console.log('  Message length:', msg.length);
  console.log('  Message (hex):', msg.toString('hex'));
  
  const command = msg.slice(i, i + 1).readUInt8();
  i += 1;
  const ATYP = msg.slice(i, i + 1).readUInt8();
  i += 1;
  
  console.log('  Command:', command);
  console.log('  ATYP:', ATYP);
  
  let host, port;
  if (ATYP === 1) { // IPv4
    host = msg.slice(i, i + 4).join('.');
    i += 4;
  } else if (ATYP === 3) { // Domain name
    const domainLength = msg.slice(i, i + 1).readUInt8();
    i += 1;
    host = new TextDecoder().decode(msg.slice(i, i + domainLength));
    i += domainLength;
  } else if (ATYP === 4) { // IPv6
    host = msg.slice(i, i + 16).reduce((s, b, idx, arr) => 
      (idx % 2 ? s.concat(arr.slice(idx - 1, idx + 1)) : s), [])
      .map(b => b.readUInt16BE(0).toString(16)).join(':');
    i += 16;
  }
  
  console.log('  Host:', host);
  
  port = msg.slice(i, i + 2).readUInt16BE(0);
  i += 2;
  
  console.log('  Port:', port);
  
  // 跳过最后的CRLF
  i += 2;
  
  console.log('  Data start index:', i);
  console.log('  Remaining data (hex):', msg.slice(i).toString('hex'));
  
  // 发送socks5成功的响应
  const response = Buffer.alloc(10);
  response[0] = 0x05; // SOCKS5 version
  response[1] = 0x00; // Success
  response[2] = 0x00; // Reserved
  response[3] = 0x01; // IPv4
  response[4] = 0x00; // Dummy IP
  response[5] = 0x00;
  response[6] = 0x00;
  response[7] = 0x00;
  response[8] = 0x00; // Dummy port
  response[9] = 0x00;
  ws.send(response);
  
  const duplex = createWebSocketStream(ws);
  
  resolveHost(host)
    .then(resolvedIP => {
      console.log(`Connecting to ${resolvedIP}:${port}`);
      net.connect({ host: resolvedIP, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', (error) => {
        console.error(`Connection error to ${resolvedIP}:${port}`, error.message);
      });
    })
    .catch(error => {
      console.error(`DNS resolution failed for ${host}:`, error.message);
      net.connect({ host, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', (error) => {
        console.error(`Connection error to ${host}:${port}`, error.message);
      });
    });
  
  return true;
}

const getDownloadUrl = () => {
  const arch = os.arch(); 
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    if (!NEZHA_PORT) {
      return 'https://arm64.ssss.nyc.mn/v1';
    } else {
        return 'https://arm64.ssss.nyc.mn/agent';
    }
  } else {
    if (!NEZHA_PORT) {
      return 'https://amd64.ssss.nyc.mn/v1';
    } else {
        return 'https://amd64.ssss.nyc.mn/agent';
    }
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;  // 不存在nezha变量时不下载文件
  
  try {
    const url = getDownloadUrl();
    // console.log(`Start downloading file from ${url}`);
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('npm download successfully');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch (e) {
    //进程不存在时继续运行nezha
  }

  await downloadFile();
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    // 检测哪吒v0是否开启TLS
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      // 检测哪吒v1是否开启TLS
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      
      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    console.log('NEZHA variable is empty, skip running');
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('npm running error:', err);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }   
}; 

async function addAccessTask() {
  if (!AUTO_ACCESS) return;

  if (!DOMAIN) {
    // console.log('URL is empty. Skip Adding Automatic Access Task');
    return;
  }
  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", {
      url: fullURL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // console.error('Error adding Task:', error.message);
  }
}

const delFiles = () => {
  fs.unlink('npm', () => {});
  fs.unlink('config.yaml', () => {}); 
};

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(() => {
    delFiles();
  }, 180000); // 180s
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
  
  // 运行SHA-224测试
  testSHA224().catch(console.error);
  
  // 运行Trojan密码测试
  testTrojanPassword().catch(console.error);
});

// 添加一个测试函数来验证SHA-224实现
async function testSHA224() {
  const testInput = "123456";
  const expectedOutput = "8949086575601d601541290782486ed0e113510300d41493ad63741f";
  const actualOutput = await sha224(testInput);
  
  console.log("SHA-224 Test:");
  console.log("  Input:", testInput);
  console.log("  Expected:", expectedOutput);
  console.log("  Actual:", actualOutput);
  console.log("  Match:", expectedOutput === actualOutput);
}

// 添加一个测试函数来验证Trojan协议密码哈希
async function testTrojanPassword() {
  const testPassword = "5efabea4-f6d4-91fd-b8f0-17e004c89c60"; // 默认UUID
  const expectedHash = "bacb8e079d2c14d60180c503457ebae5479576e2272c537404a2a4fb";
  const actualHash = await sha224(testPassword);
  
  console.log("Trojan Password Hash Test:");
  console.log("  Password:", testPassword);
  console.log("  Expected hash:", expectedHash);
  console.log("  Actual hash:", actualHash);
  console.log("  Hash match:", expectedHash === actualHash);
}
