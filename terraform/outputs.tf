output "db_private_ip" {
  value = try(module.neo4j.private_ip, "")
}

output "opensearch_endpoint" {
  value = try(module.opensearch.opensearch_endpoint, "")
}