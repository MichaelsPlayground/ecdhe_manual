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
    var publicBob = privateBob.publicKey;
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
    var ciphertext = aesGcmEncryptToBase64(secretBobBytes, nonce, plaintext);
    printC('ciphertext: ' + ciphertext);

    printC('\n*** now running ECDHE ***');
    printC('all we have is Bobs = recipients public key');
    var publicBobHex = publicBob.toHex();
    printC('pubBob hex: ' + publicBobHex);
    var publicRecipient = ec.hexToPublicKey(publicBobHex);
    printC('pubRec hex: ' + publicRecipient.toHex());

    // constants
    var NONCEBYTES = 12; // AES GCM recommended nonce length = 96 bit = 12 byte
    var PUBLICKEYBYTES = 32;
    var MACBYTES = 16; // AES GCM recommended tag length = 128 bit = 16 byte
    var SEALBYTES = PUBLICKEYBYTES + MACBYTES;
    printC('now we generate the ephemeral keypair');
    var privateEphemeral = ec.generatePrivateKey();
    var publicEphemeral = privateEphemeral.publicKey;
    printC('we generate the sharedSecret from ephemeral keypair');
    var secretShareBobEphemeral = computeSecret(privateBob, publicEphemeral);
    var secretShareEphemeralBob = computeSecret(privateEphemeral, publicBob);
    printC('secretShareEphemeralBob base64: ' + base64Encoding(Uint8List.fromList(secretShareEphemeralBob)));
    printC('secretShareBobEphemeral base64: ' + base64Encoding(Uint8List.fromList(secretShareBobEphemeral)));
    printC('we are hashing the ephemeral publicKey and Bobs publicKey with Blake2b');
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

    // lib for blake2b
    // https://pub.dev/packages/pointycastle pointycastle: ^3.5.2
    // https://github.com/bcgit/pc-dart

    // generate nonce by hashing the public keys with Blake2b
    var nonceBlake2b = getNonceByBlake2b(publicEphemeral.toHex(), publicRecipient.toHex(), NONCEBYTES);
    // todo: check nonce length and NOT filled with 'x00'
    printC('nonceBlake2b base64: ' + base64.encode(nonceBlake2b));
    // generate ecdh key
    var secretKeySender = computeSecret(privateEphemeral, publicRecipient);
    printC('secretKeySender base64: ' + base64Encoding(Uint8List.fromList(secretKeySender)));
    // encrypt the plaintext
    var ciphertextSender = aesGcmEncryptToUint8List(secretKeySender, nonceBlake2b, plaintext);
    printC('ciphertextSender base64: ' + base64Encoding(ciphertextSender));

    // convert publicEphemeralUint8List.length to byte array
    // first convert the publicEphemeral to a Uint8List
    Uint8List publicEphemeralUint8List = createUint8ListFromHexString(publicEphemeral.toHex());
    int publicEphemeralLength = publicEphemeralUint8List.lengthInBytes;
    printC('publicEphemeralLength: ' + publicEphemeralLength.toString());
    String publicEphemeralLengthHex = publicEphemeralLength.toRadixString(16).padLeft(4, '0');
    printC('publicEphemeralLengthHex: ' + publicEphemeralLengthHex); //
    var publicEphemeralLengthHexUint8List = createUint8ListFromString(publicEphemeralLengthHex);
    printC('publicEphemeralLengthHexUint8List length: ' + publicEphemeralLengthHexUint8List.lengthInBytes.toString());

    // the output is publicEphemeralLength publicEphemeral ciphertext
    var bbSender = BytesBuilder();
    printC('publicEphemeral hex: ' + publicEphemeral.toHex());
    bbSender.add(publicEphemeralLengthHexUint8List); // length of the following publicEphemeral
    bbSender.add(createUint8ListFromHexString(publicEphemeral.toHex()));
    bbSender.add(ciphertextSender);
    var sealedBoxSender = bbSender.toBytes();
    var sealedBoxSenderBase64 = base64Encoding(sealedBoxSender);
    printC('sealedBox base64: ' + sealedBoxSenderBase64);

    printC('\n*** decryption on Bobs = recipients side ***');
    printC('Bob receives the sealedBoxSenderBase64');
    var sealedBoxRecipient = base64Decoding(sealedBoxSenderBase64);
    printC('sealedBoxRecipientLength: ' + sealedBoxRecipient.lengthInBytes.toString());
    // split the sealedBox in publicKeySenderLength, publicKeySender and ciphertext
    Uint8List publicKeySenderLengthUint8List = new Uint8List.sublistView(sealedBoxRecipient, 0, 4);
    printC('publicKeySenderLengthUint8List length: ' + publicKeySenderLengthUint8List.lengthInBytes.toString());
    // convert the data back to int
    String publicEphemeralLengthHexBack = new String.fromCharCodes(publicKeySenderLengthUint8List);
    printC('publicEphemeralLengthHexBack: ' + publicEphemeralLengthHexBack);
    int publicKeySenderLength = int.parse(publicEphemeralLengthHexBack, radix: 16);
    //int publicEphemeralLengthBack = int.parse('0041', radix: 16);
    printC('publicKeySenderLength: ' + publicKeySenderLength.toString());
        // now split the data
    Uint8List publicKeySender = new Uint8List.sublistView(sealedBoxRecipient, 4, (4 + publicKeySenderLength));
    Uint8List ciphertextReceived = new Uint8List.sublistView(sealedBoxRecipient, (4 + publicKeySenderLength), sealedBoxRecipient.lengthInBytes);
    // build the ephemeralPublicKey
    var publicKeySenderFromUint8List = ec.hexToPublicKey(bin2hex(publicKeySender));
    printC('publicKeySender hex: ' + publicKeySenderFromUint8List.toHex());
    // now get the nonce from publicKeySender/Ephemeral and publicKeyBob
    var nonceBlake2bReceiver = getNonceByBlake2b(publicKeySenderFromUint8List.toHex(), publicRecipient.toHex(), NONCEBYTES);
    printC('nonceBlake2bReceiver base64: ' + base64.encode(nonceBlake2bReceiver));
    // now generate the shared secret
    //var secretKeyRecipient = computeSecret(privateBob, publicKeySenderFromUint8List);
    var secretKeyRecipient = computeSecret(privateBob, publicEphemeral);
    printC('secretKeyRecipient base64: ' + base64Encoding(Uint8List.fromList(secretKeyRecipient)));
    // decrypt the ciphertext
    printC('ciphertextReceived base64: ' + base64Encoding(ciphertextReceived));
    // secretKeySender, nonce,
    //String cleartext = aesGcmDecryptFromUint8List(secretKeySender, nonce, ciphertextReceived);
    String cleartext = aesGcmDecryptFromUint8List(secretKeyRecipient, nonceBlake2bReceiver, ciphertextReceived);
    printC('the decrypted data: ' + cleartext);

    /*
    printC('the actual time is:');
    for( var i = 0 ; i < 30; i++) {
      var now = DateTime.now();
      printC(now.toString());
    }*/
  }

  String aesGcmEncryptToBase64(
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

  Uint8List aesGcmEncryptToUint8List(
      List<int> key, Uint8List nonce, String plaintext) {
    print('** aesGcmEncrypt key: ' + base64Encoding(Uint8List.fromList(key)) + ' nonce: ' + base64Encoding(nonce));
    try {
      var plaintextUint8 = createUint8ListFromString(plaintext);

      final cipher = pc.GCMBlockCipher(pc.AESEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(Uint8List.fromList(key)), 128, nonce, Uint8List(0));
      cipher.init(true, aeadParameters);
      var ciphertextWithTag = cipher.process(plaintextUint8);
      return ciphertextWithTag;
      /*
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
          gcmTagBase64;*/
    } catch (error) {
      return Uint8List(0);
    }
  }

  String aesGcmDecryptFromUint8List(List<int> key, Uint8List nonce, Uint8List ciphertext)
       {
         print('** aesGcmDecrypt key: ' + base64Encoding(Uint8List.fromList(key)) + ' nonce: ' + base64Encoding(nonce));
    try {
      final cipher = pc.GCMBlockCipher(pc.AESEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(Uint8List.fromList(key)), 128, nonce, Uint8List(0));
      cipher.init(false, aeadParameters);
      return String.fromCharCodes(cipher.process(ciphertext));
    } catch (error) {
      printC('error: ' + error.toString());
      return 'Fehler bei der Entschlüsselung';
    }
  }

  String aesGcmIterPbkdf2DecryptFromBase64(
      String password, String iterations, String data) {
    try {
      var parts = data.split(':');
      var salt = base64Decoding(parts[0]);
      var nonce = base64Decoding(parts[1]);
      var ciphertext = base64Decoding(parts[2]);
      var gcmTag = base64Decoding(parts[3]);
      var bb = BytesBuilder();
      bb.add(ciphertext);
      bb.add(gcmTag);
      var ciphertextWithTag = bb.toBytes();
      var passphrase = createUint8ListFromString(password);
      final PBKDF2_ITERATIONS = int.tryParse(iterations);
      pc.KeyDerivator derivator =
      new pc.PBKDF2KeyDerivator(new pc.HMac(new pc.SHA256Digest(), 64));
      pc.Pbkdf2Parameters params =
      new pc.Pbkdf2Parameters(salt, PBKDF2_ITERATIONS!, 32);
      derivator.init(params);
      final key = derivator.process(passphrase);
      final cipher = pc.GCMBlockCipher(pc.AESFastEngine());
      var aeadParameters =
      pc.AEADParameters(pc.KeyParameter(key), 128, nonce, Uint8List(0));
      cipher.init(false, aeadParameters);
      return new String.fromCharCodes(cipher.process(ciphertextWithTag));
    } catch (error) {
      printC('error: ' + error.toString());
      return 'Fehler bei der Entschlüsselung';
    }
  }

  // awaits the publicKeys as hex encoded strings, returns the hashed result
  Uint8List getNonceByBlake2b(String publicKeySender, String publicKeyRecipient, int nonceBytes) {
    var dig = pc.Blake2bDigest(digestSize: nonceBytes);
    //var input = createUint8ListFromHexString(publicBob.toCompressedHex());
    var input = createUint8ListFromHexString(publicKeySender);
    printC('input = pubKey length: ' + input.lengthInBytes.toString());
    dig.update(input, 0, input.length);
    input = createUint8ListFromHexString(publicKeyRecipient);
    dig.update(input, 0, input.length);
    Uint8List nonceNew = new Uint8List(nonceBytes);
    var number = 0;
    number = dig.doFinal(nonceNew, 0);
    return nonceNew;
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

  //----------------------------------------------------------------
  /// Represent bytes in hexadecimal
  ///
  /// If a [separator] is provided, it is placed the hexadecimal characters
  /// representing each byte. Otherwise, all the hexadecimal characters are
  /// simply concatenated together.
  String bin2hex(Uint8List bytes, {String? separator, int? wrap}) {
    var len = 0;
    final buf = StringBuffer();
    for (final b in bytes) {
      final s = b.toRadixString(16);
      if (buf.isNotEmpty && separator != null) {
        buf.write(separator);
        len += separator.length;
      }
      if (wrap != null && wrap < len + 2) {
        buf.write('\n');
        len = 0;
      }
      buf.write('${(s.length == 1) ? '0' : ''}$s');
      len += 2;
    }
    return buf.toString();
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
