// ignore_for_file: implementation_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:bonus4/src/consants/strings.dart';
import 'package:bonus4/src/providers/storage_provider.dart';
import 'package:hive/hive.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:teledart/teledart.dart';
import 'package:teledart/telegram.dart';

class Bot {
  late Telegram telegram;
  late Event event;
  late TeleDart teledart;
  final _keyGen = RSAKeyGenerator();
  final StorageProvider _storageProvider = StorageProvider();
  final String apiKey = Strings.apiKey;
  Bot() {
    telegram = Telegram(apiKey);
  }

  Future<void> run() async {
    event = Event((await telegram.getMe()).username!);
    await _storageProvider.open();
    teledart = TeleDart(
      apiKey,
      event,
    );
    teledart.start();
    _registerHandlers();
  }

  void _registerHandlers() {
    teledart.onMessage(entityType: 'bot_command', keyword: 'start').listen(
          (message) => teledart.sendMessage(
            message.chat.id,
            'Добро пожаловать в RSA бота! Используйте команду /help для того чтобы узнать что я умею',
          ),
        );
    teledart.onMessage(entityType: 'bot_command', keyword: 'help').listen(
          (message) => teledart.sendMessage(
            message.chat.id,
            'Вот список команд которыми можно воспользоваться:\n'
            '/start - показывает приветственное сообщение\n'
            '/help - показывает это сообщение\n'
            '/gen {l} - создает публичный и приватный ключи для шифрования\n'
            '/enc {pubkey} {data} - зашифровывает данны при помощи публичного ключа\n'
            '/dec {data} - расшифровывает данные при помощи приватного ключа',
          ),
        );
    teledart.onMessage(entityType: 'bot_command', keyword: 'gen').listen(
      onDone: () {
        teledart.start();
      },
      (message) async {
        teledart.sendMessage(
            message.chat.id, 'Пожалуйста, введите длину ключа');
        final msg = await teledart.onMessage().first;
        try {
          final int l = int.parse(msg.text!);
          try {
            _keyGen.init(
              ParametersWithRandom(
                RSAKeyGeneratorParameters(
                  BigInt.from(17),
                  l,
                  5,
                ),
                SecureRandom('Fortuna')
                  ..seed(
                    KeyParameter(
                      Platform.instance.platformEntropySource().getBytes(32),
                    ),
                  ),
              ),
            );
            final keys = _keyGen.generateKeyPair();
            await _storageProvider.putKey(
                message.chat.id, keys.privateKey as RSAPrivateKey);
            teledart.sendMessage(
              message.chat.id,
              '${(keys.publicKey as RSAPublicKey).publicExponent.toString()} - e, ${(keys.publicKey as RSAPublicKey).modulus.toString()} - n',
            );
          } on ArgumentError catch (e) {
            teledart.sendMessage(message.chat.id, e.message);
          }
        } on Exception catch (_) {
          teledart.sendMessage(message.chat.id, 'Неверный параметр!');
        }
      },
    );
    teledart.onMessage(entityType: 'bot_command', keyword: 'enc').listen(
      (message) async {
        message.reply('Пожалуйста введите модуль!');
        final modstr = await teledart.onMessage().first;
        message.reply('Пожалуйста введите экспоненту!');
        final expstr = await teledart.onMessage().first;
        try {
          final BigInt modulus = BigInt.parse(modstr.text!);
          final BigInt exponenta = BigInt.parse(expstr.text!);
          final engine = PKCS1Encoding(RSAEngine())
            ..init(
              true,
              PublicKeyParameter<RSAPublicKey>(
                RSAPublicKey(
                  modulus,
                  exponenta,
                ),
              ),
            );
          teledart.sendMessage(
              message.chat.id, 'Пожалуйста, введите данные для шифрования');
          final text = await teledart.onMessage().first;
          final Uint8List input = Uint8List.fromList(
            utf8.encode(text.text!),
          );
          try {
            final numBlocks = input.length ~/ engine.inputBlockSize +
                ((input.length % engine.inputBlockSize != 0) ? 1 : 0);
            final output = Uint8List(numBlocks * engine.outputBlockSize);
            var inputOffset = 0;
            var outputOffset = 0;
            while (inputOffset < input.length) {
              final chunkSize =
                  (inputOffset + engine.inputBlockSize <= input.length)
                      ? engine.inputBlockSize
                      : input.length - inputOffset;

              outputOffset += engine.processBlock(
                  input, inputOffset, chunkSize, output, outputOffset);

              inputOffset += chunkSize;
            }
            Uint8List result = (output.length == outputOffset)
                ? output
                : output.sublist(0, outputOffset);
            teledart.sendMessage(
              message.chat.id,
              base64Encode(result),
            );
          } on ArgumentError catch (e) {
            teledart.sendMessage(message.chat.id, e.message);
          }
        } on Exception catch (_) {
          teledart.sendMessage(message.chat.id, 'Неверные данные!');
        }
      },
    );
    teledart.onMessage(entityType: 'bot_command', keyword: 'dec').listen(
      (message) async {
        teledart.sendMessage(message.chat.id, 'Введите текст для расшифровки:');
        final msg = await teledart.onMessage().first;
        final String cipherText = msg.text!;
        try {
          final key = await _storageProvider.readKey(message.chat.id);
          final engine = PKCS1Encoding(RSAEngine())
            ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
          try {
            final input = base64Decode(cipherText);
            final numBlocks = input.length ~/ engine.inputBlockSize +
                ((input.length % engine.inputBlockSize != 0) ? 1 : 0);
            final output = Uint8List(numBlocks * engine.outputBlockSize);
            var inputOffset = 0;
            var outputOffset = 0;
            while (inputOffset < input.length) {
              final chunkSize =
                  (inputOffset + engine.inputBlockSize <= input.length)
                      ? engine.inputBlockSize
                      : input.length - inputOffset;

              outputOffset += engine.processBlock(
                  input, inputOffset, chunkSize, output, outputOffset);

              inputOffset += chunkSize;
            }
            Uint8List result = (output.length == outputOffset)
                ? output
                : output.sublist(0, outputOffset);
            teledart.sendMessage(
              message.chat.id,
              utf8.decode(result),
            );
          } on ArgumentError catch (e) {
            teledart.sendMessage(message.chat.id, e.message);
          } on FormatException catch (_) {
            teledart.sendMessage(message.chat.id, 'Неверные входные данные!');
          }
        } on HiveError catch (_) {
          teledart.sendMessage(message.chat.id,
              'Для начала вам необходимо сгенерировать пару ключей');
        }
      },
    );
  }
}
