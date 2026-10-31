"""The AWS runtime's adapters for cascadesec_core's ports (portable-runtime-
spec §2, §3). The only package here that imports a cloud SDK: the core
never does, and an adapter stores what it is told and decides nothing.

  records   RecordStore on a DynamoDB table
"""
