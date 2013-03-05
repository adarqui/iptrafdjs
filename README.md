Just a quick concept code to monitor network traffic using live pcap captures or logs.

Two live demos:

nodejs example: https://adarq.strangled.net:65503
- Allows you to view live traffic ('flows', 'top talkers', & 'summary') on my system
- Also has the live bandwidth monitor & top talkers charts

client side: http://adarq.strangled.net:65500/iptrafdjs/web
- Only permits 'manual' mode (paste capture files)

The iptraf_parser.pl script can be pretty useful. Condense large pcap captures & then paste it into the manual textbox in the 'control panel':

- perl iptraf_parser.pl --in pcap.txt --condense > pcap_condensed.txt



web/include.js gives an 'overview' of the object structure of the code, helpful when trying to find the layout of object literals/definitions/methods

alot of features unfinished => wanted to code something else :F

pc
