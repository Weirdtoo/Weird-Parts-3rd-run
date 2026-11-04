import 'package:drift/drift.dart';

/// Public signed lifecycle history. Never stores credential material.
class CompanyUserEvents extends Table {
  TextColumn get companyId => text()();
  TextColumn get userId => text()();
  IntColumn get sequence => integer()();
  TextColumn get requestId => text()();
  TextColumn get publicHead => text()();
  TextColumn get previousHead => text()();
  TextColumn get certificateBytes => text()();
  TextColumn get kind => text()();
  @override
  Set<Column> get primaryKey => {companyId, userId, sequence};
  @override
  List<Set<Column>> get uniqueKeys => [
    {companyId, userId, requestId},
  ];
}

class CompanyUserDeliveries extends Table {
  TextColumn get companyId => text()();
  TextColumn get userId => text()();
  TextColumn get publicHead => text()();
  TextColumn get peerDeviceId => text()();
  TextColumn get sourceDeviceId => text()();
  TextColumn get bindingCommitment => text()();
  TextColumn get receiptBytes => text()();
  @override
  Set<Column> get primaryKey => {
    companyId,
    userId,
    publicHead,
    bindingCommitment,
  };
}

class CompanyUserCredentialGrants extends Table {
  TextColumn get companyId => text()();
  TextColumn get userId => text()();
  TextColumn get grantKey => text()();
  TextColumn get grantBytes => text()();
  @override
  Set<Column> get primaryKey => {companyId, userId, grantKey};
}
