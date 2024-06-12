import 'package:hive/hive.dart';
import 'package:pointycastle/export.dart';

class StorageProvider {
  late BoxCollection collection;
  late CollectionBox<Map<dynamic, dynamic>> keys;
  Future<void> open() async {
    collection = await BoxCollection.open(
      'data',
      {'keys'},
      path: './',
      key: HiveAesCipher(
        Hive.generateSecureKey(),
      ),
    );
    keys = await collection.openBox<Map>('keys');
  }

  Future<void> putKey(int id, RSAPrivateKey key) async {
    await keys.put(id.toString(), {
      'modulus': key.n,
      'pexp': key.privateExponent,
      'p': key.p,
      'q': key.q,
    });
  }

  Future<RSAPrivateKey> readKey(
    int id,
  ) async {
    final Map<dynamic, dynamic>? res = await keys.get(id.toString());
    if (res == null) {
      throw HiveError('no such element');
    }
    return RSAPrivateKey(
      res['modulus'],
      res['pexp'],
      res['p'],
      res['q'],
    );
  }
}
