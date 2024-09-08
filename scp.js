const fs = require('fs');

const proxies = [];
const output_file = 'proxy.txt';

if (fs.existsSync(output_file)) {
  fs.unlinkSync(output_file);
  console.log(`'${output_file}' telah dihapus.`);
  console.log(`Wait For 10s`)
}

const raw_proxy_sites = [
"https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
"https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
"https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",
"https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
"https://raw.githubusercontent.com/zloi-user/hideip.me/main/connect.txt",
"https://raw.githubusercontent.com/zevtyardt/proxy-list/main/all.txt",
"https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
"https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/working.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/ultrafast.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/premium.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/new.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/fast.txt",
"https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
"https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/old-data/Proxies.txt",
"https://api.proxyscrape.com/v2/?request=displayproxies",
"https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all&ssl=all&anonymity=all",
"https://api.proxyscrape.com/?request=displayproxies&proxytype=http",
"https://api.openproxylist.xyz/socks5.txt",
"https://api.openproxylist.xyz/socks4.txt",
"https://api.openproxylist.xyz/http.txt",
"https://api.good-proxies.ru/getfree.php?count=1000&key=freeproxy",
];

async function fetchProxies() {
  for (const site of raw_proxy_sites) {
    try {
      const response = await fetch(site);
      if (response.ok) {
//console.log(`success: ${site}`);
        const data = await response.text();
        const lines = data.split('\n');
        for (const line of lines) {
          if (line.includes(':')) {
            const [ip, port] = line.split(':', 2);
            proxies.push(`${ip}:${port}`);
          }
        }
      } else {
//console.log(`skip: ${site}`);
      }
    } catch (error) {
//console.error(`skip: ${site}`);
    }
  }

  fs.writeFileSync(output_file, proxies.join('\n'));
  fs.readFile(output_file, 'utf8', (err, data) => {
    if (err) {
      console.error('Gagal membaca file:', err);
      return;
    }
    const proxies = data.trim().split('\n');
    const totalProxies = proxies.length;
    console.log(`success scraping ${totalProxies} proxy`);
  });
}
fetchProxies();