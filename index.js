const zlib = require("zlib");
const cp = require("child_process");

// filter sent packets with some spam removed
// udp && ip.src == 192.168.1.98 && (data.len < 96 || data.len > 157) && data.len != 25 && data.len != 89 && data.len != 198 && data.len != 204 && (data.len < 195 || data.len > 210) && (data.len < 183 || data.len > 184)

// random packets from wireshark from doing random stuff in game
// these packets contain compressed gzip data, however i dont know anything else about them such as the data at the start. probably not game related data tho
// game sometimes sends ~25 byte packets that dont have any gzip data at all. fuck knows what these are too
// these packets can contain multiple gzip data
const packets = [
    // "0001050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c6102b2375fbc16043303a82a5118482b0231230304904bb3a0d142509a198d668462747118cd0ec485b6614e5cd795f73230381e42b707a2aec11e4623c41919d2c0e013546e813d135ebdb8fd02d30700482f8a8b74010000",
    // "00001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc1426207bf3c56b41207166202ec82f666007d236d6614ecab7db1d5efd733804932bca2f01cb014183a8b8aa038801006c6e72d678000000",
    // "00001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc1426064606b6a28ed50c507dcc405c905fccc00ea40f31b11de636beef3079dfe1c330b9a2fc12b01c103430400100535f24497c000000",
    // "0001050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c6102b2375fbc16043303a82a5118482b0231230304904bb3a0d142509a198d668462747118cd0ec485b6614e5cd7956d18181c0fa1db0351d7600fa311e28c0c6960f0092ab7c09e09af5edc7e81e9030012c82ec074010000",
    // "010000000000000001000000010000f00000dec1064b2ab6270000004a01020000001f8b080000000000000a1362606060026216282ea92c4805d19c409c919897529c91989d0a956307e2d2e2d4a2f8cc14a01e4686284e735b46060146008f41502144000000",
    // "0100000000000121e2000029700000edc64b2b83a900df87050000008b01010000001f8b080000000000000a136260606041c2259505a9209a078813934bf28be28164667e1e488c032e9699c2c4c0c870e9f999d90c507d6c1039a04a089f0f88e30b72122be30b128b4a3293735211ea802289b9c50c0cc2403633543fc8bee2dcc49c9cf862a0aee20c76205f2761b3d38cca03fbbf5cd9eac408e4833000aef05bcdb0000000"
    // "0100000000000055670000004f0000efb24b2ab73100dec10600000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc142620fbb3af8d30489c19880bf28b19d881b4f751d6c312eb4e395ca83a76182657945f029603820606280000227dcf43780000000000005f001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc1426209b91719f3f489c19880bf28b19d881b41fff5b2706860087fd73ff1f84c915e59780e580a081010a00f9c5b02e78000000000000c601050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c61626064b8f4fccc6c062473802a138581b4221033324000361a1da38bc3cce401e2a2fc94f8e292a2d2f4f41cb01b4140084a330355cf9a09023bed41ec343078b69f11499e07ce46a5d981d82371b393c7c359fbb9ae6f75427713445d03d8dcefff41e0bd3db2b910bb3ed943d42db06742f327423f84812b1c40fa38811800447e5f359401000000000066001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc14260646864bcfcfcc6680ea6306e282fc620676207d916d93d38da7cc8e1cea9b9d607245f92560392068b86baa7d00c40000055d71fb7c00000000000060001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc142620fbb3af8d30489c19880bf28b19d881f4ee13ac874f369e72b85571ec304cae28bf042c07040d0c5000003c9aed2c780000000000008b01010000001f8b080000000000000a136260606041c2259505a9209a078813934bf28be28164667e1e488c032e9699c2c4c0c870e9f999d90c507d6c1039a04a089f0f88e30b72122be30b128b4a3293735211ea802289b9c50c0cc2403633543fc8bee2dcc49c9cf862a0aee20c76205f3361b3d3845707f67fbbb2d58911c8076100ec246162b0000000000000c601050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c61626064b8f4fccc6c062473802a138581b4221033324000361a1da38bc3cce401e2a2fc94f8e292a2d2f4f41cb01b4140084a330355cf9a09023bed41ec343078b69f11499e07ce46a5d981d82371b393c7c359fbb9ae6f75427713445d03d8dcefff41e0bd3db2b910bb3ed943d42db06742f327423f84812b1c40fa38811800447e5f359401000000000066001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc14260646864bcfcfcc6680ea6306e282fc620676207d916d93d38da7cc8e1cea9b9d607245f92560392068b86baa7d00c40000055d71fb7c0000000000005f001f8b080000000000000a136260606041c2259505a9209a078813934bf28be24b0b52124bc0621c70b1cc142620fbb3af8d30489c19880bf28b19d881b4f459d6c3957ea71ce4ca8e1d86c915e59780e580a081010a009804916478000000000000c601050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c61626064b8f4fccc6c062473802a138581b4221033324000361a1da38bc3cce401e2a2fc94f8e292a2d2f4f41cb01b4140084a330355cf9a09023bed41ec343078b69f11499e07ce46a5d981d82371b393c7c359fbb9ae6f75427713445d03d8dcefff41e0bd3db2b910bb3ed943d42db06742f327423f84812b1c40fa38811800447e5f359401000000000066001f8b080000000000000a136260606041c2259505a9209a",
    // "01000000000000da9f0003eacd0000ef2801a766514bf355e50000009601010000001f8b080000000000000a136260606041c2259505a9209a078813934bf28be28164667e1e488c032e9699c20464db8a7b4a83c4d920e240551033b880383e3923312f3d15a81222065253905894985bccc0200c643302b11092bd20f3606a59813835b7a0a41249be38b32a959901041aec417c10bb28350dac8f01aa861d880b4b137332813a61e200c7a99c20e0000000",
    // "01000000000000ac360001ae870000ee6301a76651097f38650000009601010000001f8b080000000000000a136260606041c2259505a9209a078813934bf28be28164667e1e488c032e9699c20464db8a7b4a83c4d920e240551033b880383e3923312f3d15a81222065253905894985bccc0200c643302b11092bd20f3606a59813835b7a0a41249be38b32a959901041aec417c10bb28350dac8f01aa861d880b4b137332813a61e200c7a99c20e0000000",
    // "01000000000000f05a000280d80000f00001a9db490981bf5e0000018301010000001f8b080000000000000a5552596ec430084df77def012a553d504f60791c1a5b93892d2053e5f6053b4ed28f97c00363c0efb5699af30d784aa0ff7b81751cd1c837c441b9eb850beda9d8dffeeb53f9cbc24b56a9f12230636a2d8371910ec0c1d15c5f7393457b10e24dec13c1abe0698e5f0928810b40d9bf5b7de32c2f39c932030ed97f5a7d43298ad166fe41790c078b93f4d1479cefd0d95226ccaf0f0cb506818b43bb662b7fab7cc945299bb933819f7bb929b671187f87b9be9e198716907c402edcc73fce7468930fce707177237680b55e3c2e47f3d9f72d678e406c621f8eb9ef0b7db3c03d6c66cbbef941b0fba9ee7c17773bc092f3b8f8a6851f3bf6bcce05132cbb13db105bec43e76b2f8a21d2a211b5758bb42ffd6b3f8738b26f562d645f66747b8e91bdae71d99d750e88224e4dd143bde3611b332e749b7a2b6f079914abb69effc5c8db16e87cd6d7cacb542216e7379ab7a1affa565b8556633d7454df406d93e44e92e2519e4214f1071e683b4a40030000",
    // "0001050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c6102b20333549561660055250a03694520666480006c343ac6a60e641e0f1017e5a7c417971495a6a7e780dd070242509a19a87ad64c10d8690f62a781c1b3fd8c7079843a16343176200edae1eac4c020e0d07f88f520ba9b20ea1aec6134239259107b3e41e516d833a1b91d552f4303ae3000e9e3046200528a919d8c010000",
    // "01000000000002f94a0007c7660000ec9801ae39354bfa2bf50000008c01020000001f8b080000000000000a1362606060076216282ea92c4865818ae5a6161727a6a73260e3b302b16aa9954206541f889f9c9f935f04e57300715a5a9a518a59b2014c3e273f39310748333240004c5d417e716649667e1ec88ee916e64ecab7db1da2eb9d0fc2dc54959f0776134c0f17542c3ebf3c2f1568211390ff1f080034ea8fe5cc000000",
    // "0100000000000306d10008102a0000ed5201aeb77d4bfaa8f50000009901020000001f8b080000000000000a1362606060076216282ea92c4865818ae5a6161727a6a73260e3cb00b16aa995424a71624a62311401d9c55001901a56204ececfc92f829acd01c4696969462966c90630f99cfce4c41c20cdc80001307505f9c5992599f979207ba75b983b29df6e7788ae773e087367557e1ed89d303d5c50b1f8fcf2bc54a0854c40fe7f200000dda81e4de0000000",
    // "010000000000039dab0008ea930000ee1001b051f34bfc430d0000009b01020000001f8b080000000000000a1362606060076216282ea92c4865818ae5a6161727a6a73260e30b01b16aa9954271766652664aa642497e664e6a09c40c56204ececfc92f829ac901c4696969462966c90630f99cfce4c41c20cdc80001307505f9c5992599f97920fba65b983b29df6e7788ae773e08735f557e1ed87d303d5c50b1f8fcf2bc54a0854c40fe7f2000005786b76bd8000000",
    // "01000000000003f63d000975d00000f00001b139f14bfd2d7d000000c501010000001f8b080000000000000a4d8f5b0ec2201045a9d647a23fd62518d7e11a5c012185b69394873c3eea974b77a6a0e1e3c0e4de9bcbd031c6da8ab83845f719117db49ee309d69076fc6b2037383fa7fb8df47dd631953b2e084f4e8aa8f8a466c9212a5dfa29eb84173a3076c5b9413ae4507cea059967d207081398917b2b7900ed6695bd2de2d5b0e69b6aff006f451e639f475b7a5f49cc109735cbeabf8a315c2bed84f42944abb9115aaddacfdb9167938965477af30b4750b7873c010000",
    // "0001050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c6102b20333549561660055250a03694520666480006c343ac6a60e6657517e0ad0a61cb0db4040084a330355ce9a09023bed11ec93fb1991e47990d82c486c26289b1d88d7b98b3815da723968c6cc3884ee266630d90036fffb7f10786f8f6c7e1a187cb287a85b600f3317533f8481cbaf4c50b70000cc65aaf494010000",
    // "0001050000001f8b080000000000000a1362606060066216282ea92c4805d162409c985c925f149f9897999b5892999f175f5a909258920a51c70197cf4c6102b20333549561660055250a0369452066648000726916345a088899a07c109d990261f301715a6671467c4e62766a7c5a517e3ac24fc59955a9cc401377c8b5be0edca1ea0062cf9a09023bed9991ec6304870523030f540cc46641623341d9ec40fcb0ea9be3d9337b1c5a5f4f3b84ee6688990df6203ddfff83c07b7b462473d2c0e013d4ee05f64c58f51f80b9ad0157d8c0f401007064c43bc4010000",
]

// // get random packet
// const buffer = Buffer.from(packets[Math.floor(Math.random() * packets.length)], "hex");

// // decompress all the gzip data
// const decompressed = decompress(buffer);
const decompressed = [
    Buffer.from("12 00 00 00 03 00 00 00 04 00 00 00 04 00 00 00 74 79 70 65 04 00 00 00 16 00 00 00 61 63 74 6f 72 5f 61 6e 69 6d 61 74 69 6f 6e 5f 75 70 64 61 74 65 00 00 04 00 00 00 08 00 00 00 61 63 74 6f 72 5f 69 64 02 00 00 00 17 ad ce 62 04 00 00 00 04 00 00 00 64 61 74 61 13 00 00 00 21 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 04 00 00 00 05 00 00 00 65 71 75 69 70 00 00 00 04 00 00 00 00 00 00 00 12 00 00 00 02 00 00 00 04 00 00 00 02 00 00 00 69 64 00 00 04 00 00 00 12 00 00 00 66 69 73 68 5f 6f 63 65 61 6e 5f 6f 63 74 6f 70 75 73 00 00 04 00 00 00 04 00 00 00 73 69 7a 65 03 00 01 00 ec 51 b8 1e 85 3b 57 40 03 00 01 00 9a 99 99 99 99 99 c9 3f 03 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 03 00 01 00 3d 84 ce 0f 9b f4 1b 0f 03 00 01 00 04 00 00 00 00 00 00 00 03 00 01 00 02 00 00 00 00 00 00 00 07 00 00 00 f6 28 f7 42 00 00 88 40 cd cc bc c1 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 03 00 00 00 00 00 80 3f 03 00 01 00 f7 ff ff ff ff ff ef 3f 01 00 00 00 00 00 00 00 03 00 01 00 66 66 66 66 66 66 f2 3f 03 00 00 00 00 00 a0 3f 02 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 03 00 00 00 00 00 c0 3f 03 00 01 00 75 77 89 3b f2 00 89 bf 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 01 00 00 00".split(" ").join(""), "hex")
];

// attempt to decode
decompressed.forEach(packet => {
    const decoded = decode(packet);

    console.log(decoded);
});

return;

const tshark = cp.spawn("C:\\Program Files\\Wireshark\\tshark.exe", "-i WiFi -f udp -T fields -e ip.src -e ip.dst -e data -E separator=, -E header=y".split(" "));

tshark.stdout.on("data", data => {
    const string = data.toString();
    string.split("\r\n").forEach(packet => {
        const [src, dest, data] = packet.split(",");
        if (!data) return;
        try {
            const buffer = Buffer.from(data, "hex");
            const decompressed = decompress(buffer);
            decompressed.forEach(decompressedPacket => {
                const decoded = decode(decompressedPacket);
                console.log({ src, dest, decoded });
                // filter messages
                const messageIndex = decoded.findIndex(i => i.value == "message") + 2;
                if (messageIndex > 1) {
                    // console.log(`${src} > ${dest}`);
                    console.log(`Found message (${src} > ${dest}):`, decoded[messageIndex].value.replace(/%u:? /, ""));
                }
            });
        } catch (err) { }
    });
});

function decode(buffer, offset = 0) {
    console.log(Array.from(buffer).map(i => i.toString(16).padStart(2, "0")).join(" "));

    const data = [];
    const unknownData = [];

    /**
     * NOTES
     * the length of every string is before the string, as 32 bit signed little endian
     * also seems that there is a 32 bit integer of 4 before strings
     * always starts with 18 as 32 bit int
     * 2nd 32 bit int unsure
     * there is a 4 byte boundary
     */

    // unknownData.push(buffer.readInt32LE(offset)) // 18, always
    // offset += 4;
    // unknownData.push(buffer.readInt32LE(offset)) // no clue, its usually either 2,3,4
    // offset += 4;

    // console.log(unknownData)

    while (offset < buffer.length) {
        // console.log(buffer.subarray(offset), data);

        // decode various types
        // if (offset >= buffer.length) break;
        const type = buffer.readInt32LE(offset);
        offset += 4;
        if (type === 2) {
            // probably int, its 32 bit
            const value = buffer.readInt32LE(offset)
            offset += 4;

            data.push({
                type: "integer???",
                value
            });
        } else
        if (type === 4) {
            // string
            const length = buffer.readInt32LE(offset);
            offset += 4;
            const stringBuffer = buffer.subarray(offset, offset + length);
            offset += length;
            offset += (4 - (offset % 4)) % 4;
            const value = stringBuffer.toString();

            data.push({
                type: "string",
                length,
                buffer: stringBuffer,
                value
            });
        } else
        if (type === 7) {
            // vector
            const x = buffer.readFloatLE(offset);
            offset += 4;
            const y = buffer.readFloatLE(offset);
            offset += 4;
            const z = buffer.readFloatLE(offset);
            offset += 4;

            data.push({
                type: "vector",
                x,
                y,
                z
            });
        } else
        if (type === 18) {
            // at the start of each packet, not sure what this means. the value is often 2-4
            const value = buffer.readInt32LE(offset);
            offset += 4;
            
            data.push({
                type: `${type}???`,
                value
            });
        } else
        if (type === 65538) {
            // not sure, seen after actor_id
            const value = buffer.readBigInt64LE(offset);
            offset += 8;
            
            data.push({
                type: `${type}???`,
                value
            });
        } else
        if (type === 65539) {
            // double
            const value = buffer.readDoubleLE(offset);
            offset += 8;
            data.push({
                type: "double",
                value,
            });
        } else {
            data.push({
                type: `${type}???`
            });
            // offset += 4; // assume value of type is 4 bytes i guess
            // console.log(`Unknown type '${type}'`);
        }
    }

    // const remainingData = buffer.subarray(offset);
    // data.push({
        // buffer: remainingData
    // })

    return data;
}

function decompress(buffer) {
    const decompressedArray = [];
    let index = null;
    let offset = 0;
    while (index !== -1) {
        const chunk = buffer.subarray(offset);
        index = chunk.findIndex((value, index, obj) => obj[index] == 0x1f && obj[index+1] == 0x8b && obj[index+2] == 0x08);
        if (index >= 0) {
            const decompressed = zlib.gunzipSync(chunk.subarray(index));
            decompressedArray.push(decompressed);
            offset += index + decompressed.length;
        }
    }
    return decompressedArray;
}
