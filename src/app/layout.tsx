import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Cyber Defender | AI-Powered Cybersecurity System",
  description: "Military-grade AI cybersecurity platform with real-time intrusion detection, malware analysis, and phishing protection.",
  keywords: ["cybersecurity", "IDS", "malware detection", "phishing", "AI security", "threat intelligence"],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){
              var BIS_ATTRS = ['bis_size','bis_status','bis_frame_id','bis_body_id','bis_chainid','bis_depth','bis_skin_checked'];
              function strip(el) {
                if (!el || el.nodeType !== 1) return;
                for (var i = 0; i < BIS_ATTRS.length; i++) el.removeAttribute(BIS_ATTRS[i]);
                var attrs = el.attributes;
                if (attrs) {
                  for (var j = attrs.length - 1; j >= 0; j--) {
                    var n = attrs[j].name;
                    if (n.indexOf('__processed_') === 0 || n.indexOf('bis_') === 0) el.removeAttribute(n);
                  }
                }
              }
              function scan(root) {
                var els = root.querySelectorAll ? root.querySelectorAll('*') : [];
                for (var i = 0; i < els.length; i++) strip(els[i]);
                strip(root);
              }
              scan(document.documentElement);
              scan(document.head);
              scan(document.body);
              var mo = new MutationObserver(function(mutations) {
                for (var m = 0; m < mutations.length; m++) {
                  if (mutations[m].type === 'attributes') strip(mutations[m].target);
                  if (mutations[m].addedNodes) {
                    for (var n = 0; n < mutations[m].addedNodes.length; n++) {
                      var node = mutations[m].addedNodes[n];
                      if (node.nodeType === 1) { strip(node); scan(node); }
                    }
                  }
                }
              });
              if (document.documentElement) mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
            })();`,
          }}
        />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased font-mono`}
        suppressHydrationWarning
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
