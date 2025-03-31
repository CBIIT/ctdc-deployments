#create alb http ingress
resource "aws_security_group_rule" "alb_http_inbound" {
  from_port         = local.http_port
  protocol          = local.tcp_protocol
  to_port           = local.http_port
  cidr_blocks       = concat(local.allowed_alb_ip_range, var.allowed_ip_blocks)
  security_group_id = module.alb.alb_securitygroup_id
  type              = "ingress"
  depends_on = [
    module.alb
  ]
}
#create alb https ingress
resource "aws_security_group_rule" "alb_https_inbound" {
  from_port         = local.https_port
  protocol          = local.tcp_protocol
  to_port           = local.https_port
  cidr_blocks       = concat(local.allowed_alb_ip_range, var.allowed_ip_blocks)
  security_group_id = module.alb.alb_securitygroup_id
  type              = "ingress"
  depends_on = [
    module.alb
  ]
}

#create ecs ingress sg
resource "aws_security_group_rule" "inbound_fargate" {
  for_each          = toset(local.fargate_security_group_ports)
  from_port         = each.key
  protocol          = local.tcp_protocol
  to_port           = each.key
  security_group_id = module.ecs.ecs_security_group_id
  cidr_blocks       = [data.aws_vpc.vpc.cidr_block]
  type              = "ingress"
}

#create app ingress
resource "aws_security_group_rule" "app_inbound" {
  for_each                 = var.microservices
  from_port                = each.value.port
  protocol                 = local.tcp_protocol
  to_port                  = each.value.port
  security_group_id        = module.ecs.app_security_group_id
  source_security_group_id = module.alb.alb_securitygroup_id
  type                     = "ingress"
  depends_on = [
    module.alb
  ]
}

#create opensearch ingress rule
  resource "aws_security_group_rule" "opensearch_inbound" {
    count = var.create_opensearch_cluster ? 1: 0
    from_port         = local.https_port
    protocol          = local.tcp_protocol
    to_port           = local.https_port
    security_group_id = module.opensearch.security_group_id
    #security_group_id = module.opensearch[count.index].opensearch_security_group_id
    type              = "ingress"
    cidr_blocks       = local.nih_cidrs
 }

#create opensearch egres rule
/*resource "aws_security_group_rule" "opensearch_outbound" {
  count             = var.create_opensearch_cluster ? 1 : 0
  from_port         = local.any_port
  protocol          = local.any_protocol
  to_port           = local.any_port
  cidr_blocks       = local.all_ips
  security_group_id = module.opensearch[count.index].opensearch_security_group_id
  type              = "egress"
}*/

# create rds mysql ingress rule
resource "aws_security_group_rule" "mysql_inbound" {
  count             = var.create_rds_mysql ? 1 : 0
  from_port         = local.mysql_port
  protocol          = local.tcp_protocol
  to_port           = local.mysql_port
  security_group_id = module.rds_mysql[count.index].security_group_id
  type              = "ingress"
  cidr_blocks       = local.nih_cidrs
}