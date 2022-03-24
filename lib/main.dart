import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

//import 'package:cryptography/dart.dart';
//import 'package:elliptic/ecdh.dart';
//import 'package:elliptic/elliptic.dart';
//import 'package:cryptography/cryptography.dart';


import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter/material.dart';

void main() => runApp(MyApp());
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter',
      home: Scaffold(
        appBar: AppBar(
          title: Text('Flutter Console'),
        ),
        body: MyWidget(),
      ),
    );
  }
}

// widget class
class MyWidget extends StatefulWidget {
  @override
  _MyWidgetState createState() => _MyWidgetState();
}

class _MyWidgetState extends State<MyWidget> {
  // state variable
  String _textString = 'press the button "run the code"';
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          'console output',
          style: TextStyle(fontSize: 30),
        ),
        Expanded(
          flex: 1,
          child: new SingleChildScrollView(
            scrollDirection: Axis.vertical,
            child: Padding(
                padding: EdgeInsets.fromLTRB(10, 5, 10, 5),
                child: Text(_textString,
                    style: TextStyle(
                      fontSize: 20.0,
                      fontWeight: FontWeight.bold,
                      fontFamily: 'Courier',
                      color: Colors.black,
                    ))),
          ),
        ),
        Container(
          child: Row(
            children: <Widget>[
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('clear console'),
                  onPressed: () {
                    clearConsole();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('extra Button'),
                  onPressed: () {
                    runYourSecondDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('run the code'),
                  onPressed: () async {
                    runYourMainDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
            ],
          ),
        ),
      ],
    );
  }

  void clearConsole() {
    setState(() {
      _textString = ''; // will add additional lines
    });
  }

  void printC(_newString) {
    setState(() {
      _textString =
          _textString + _newString + '\n';
    });
  }
  /* ### instructions ###
      place your code inside runYourMainDartCode and print it to the console
      using printC('your output to the console');
      clearConsole() clears the actual console
      place your code that needs to be executed additionally inside
      runYourSecondDartCode and start it with "extra Button"
   */
  Future<void> runYourMainDartCode() async {

    clearConsole();


    // lib for ecdh
    // https://pub.dev/packages/elliptic elliptic: ^0.3.6
    // https://github.com/C0MM4ND/dart-elliptic

    // run an ecdh regular with two keypairs
    // use elliptic curves
    printC('\n*** now running ECDH dart-elliptic ***');

    var ec = getP256();
    var priv = ec.generatePrivateKey();
    var pub = priv.publicKey;
    printC('privateKey: 0x$priv');
    printC('publicKey: 0x$pub');
    printC('pubKey hex: ' + pub.toHex());

    // use ecdh
    var privateAlice = ec.generatePrivateKey();
    var publicAlice = privateAlice.publicKey;
    var privateBob = ec.generatePrivateKey();
    var publicBob = privateAlice.publicKey;
    var secretAlice = computeSecretHex(privateAlice, publicBob);
    var secretBob = computeSecretHex(privateBob, publicAlice);
    var secretBobBytes = computeSecret(privateBob, publicAlice);
    printC('secretAlice: 0x$secretAlice');
    printC('secretBob: 0x$secretBob');
    printC('secretBob base64: ' + base64.encode(secretBobBytes));

    printC('*** now run AES 256 GCM encryption ***');
    // pointycastle: ^3.5.2
    var plaintext = 'The quick brown fox';
    printC('plaintext: ' + plaintext);
    final nonce = generateRandomNonce();
    var ciphertext = aesGcmToBase64(secretBobBytes, nonce, plaintext);
    printC('ciphertext: ' + ciphertext);

    printC('\n*** now running ECDHE ***');
    printC('all we have is Bobs keypair');
    // constants
    var NONCEBYTES = 12;
    var PUBLICKEYBYTES = 32;
    var MACBYTES = 16;
    var SEALBYTES = PUBLICKEYBYTES + MACBYTES;
    printC('now we generate the ephemeral keypair');
    var privateEphemeral = ec.generatePrivateKey();
    var publicEphemeral = privateEphemeral.publicKey;
    printC('we generate the sharedSecret from ephemeral keypair');
    printC('we are hashing the emphemeral publicKey and Bobs publicKey with Blake2b');
    /* java imp
    final Blake2b blake2b = Blake2b.Digest.newInstance( crypto_box_NONCEBYTES );
    blake2b.update(senderpk);
    blake2b.update(mypk);
    byte[] nonce = blake2b.digest();
    if (nonce == null || nonce.length!=crypto_box_NONCEBYTES) throw new IllegalArgumentException("Blake2b hashing failed");
    return nonce;
     */
    // https://pub.dev/packages/blake2b blake2b: ^0.2.2
    // https://github.com/riclava/blake2b

    // pointycastle !!

    var dig = pc.Blake2bDigest(digestSize: 12);
    //var input = createUint8ListFromHexString(publicBob.toCompressedHex());
    var input = createUint8ListFromHexString(publicEphemeral.toHex());
    printC('input = pubKey length: ' + input.lengthInBytes.toString());
    dig.update(input, 0, input.length);
    input = createUint8ListFromHexString(publicBob.toHex());
    dig.update(input, 0, input.length);
    Uint8List nonceNew = new Uint8List(12);
    var number = 0;
    number = dig.doFinal(nonceNew, 0);
    printC('number: ' + number.toString());
    printC('nonce base64: ' + base64.encode(nonceNew));
    /*
    printC('the actual time is:');
    for( var i = 0 ; i < 30; i++) {
      var now = DateTime.now();
      printC(now.toString());
    }*/
  }

  String aesGcmToBase64(
      List<int> key, Uint8List nonce, String plaintext) {
    try {
      var plaintextUint8 = createUint8ListFromString(plaintext);

      final cipher = pc.GCMBlockCipher(pc.AESEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(Uint8List.fromList(key)), 128, nonce, Uint8List(0));
      cipher.init(true, aeadParameters);
      var ciphertextWithTag = cipher.process(plaintextUint8);
      var ciphertextWithTagLength = ciphertextWithTag.lengthInBytes;
      var ciphertextLength =
          ciphertextWithTagLength - 16; // 16 bytes = 128 bit tag length
      var ciphertext =
      Uint8List.sublistView(ciphertextWithTag, 0, ciphertextLength);
      var gcmTag = Uint8List.sublistView(
          ciphertextWithTag, ciphertextLength, ciphertextWithTagLength);
      final nonceBase64 = base64.encode(nonce);
      final ciphertextBase64 = base64.encode(ciphertext);
      final gcmTagBase64 = base64.encode(gcmTag);
      return nonceBase64 +
          ':' +
          ciphertextBase64 +
          ':' +
          gcmTagBase64;
    } catch (error) {
      return 'Fehler bei der Verschlüsselung';
    }
  }


  Uint8List generateRandomNonce() {
    final _sGen = Random.secure();
    final _seed =
    Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
    pc.SecureRandom sec = pc.SecureRandom("Fortuna")
      ..seed(pc.KeyParameter(_seed));
    return sec.nextBytes(12);
  }

  Uint8List createUint8ListFromString(String s) {
    var ret = new Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  Uint8List createUint8ListFromHexString(String hex) {
    hex = hex.replaceAll(RegExp(r'\s'), ''); // remove all whitespace, if any

    var result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      var num = hex.substring(i, i + 2);
      var byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }

  String base64Encoding(Uint8List input) {
    return base64.encode(input);
  }

  Uint8List base64Decoding(String input) {
    return base64.decode(input);
  }

  void runYourSecondDartCode() {
    printC('execute additional code');
  }
}
