output "opensearch_endpoint" {
  value = try(module.opensearch.opensearch_endpoint, "")
}