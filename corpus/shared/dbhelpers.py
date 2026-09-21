def build_filter(column, value):
    return "%s = '%s'" % (column, value)


def run_query(cursor, sql):
    cursor.execute(sql)
    return cursor.fetchall()


def run_parameterized(cursor, sql, params):
    cursor.execute(sql, params)
    return cursor.fetchall()
