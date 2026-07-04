package io.github.mesubash.iam.config;

import org.hibernate.type.descriptor.ValueBinder;
import org.hibernate.type.descriptor.ValueExtractor;
import org.hibernate.type.descriptor.WrapperOptions;
import org.hibernate.type.descriptor.java.JavaType;
import org.hibernate.type.descriptor.jdbc.BasicBinder;
import org.hibernate.type.descriptor.jdbc.BasicExtractor;
import org.hibernate.type.descriptor.jdbc.JdbcType;

import java.sql.*;

public class LTreeJdbcType implements JdbcType {

    public static final LTreeJdbcType INSTANCE = new LTreeJdbcType();

    @Override
    public int getJdbcTypeCode() {
        return Types.OTHER;
    }

    @Override
    public <X> ValueBinder<X> getBinder(JavaType<X> javaType) {
        return new BasicBinder<X>(javaType, this) {
            @Override
            protected void doBind(PreparedStatement st, X value, int index, WrapperOptions options)
                    throws SQLException {
                if (value == null) {
                    st.setNull(index, Types.OTHER);
                } else {
                    st.setObject(index, javaType.unwrap(value, String.class, options), Types.OTHER);
                }
            }

            @Override
            protected void doBind(CallableStatement st, X value, String name, WrapperOptions options)
                    throws SQLException {
                if (value == null) {
                    st.setNull(name, Types.OTHER);
                } else {
                    st.setObject(name, javaType.unwrap(value, String.class, options), Types.OTHER);
                }
            }
        };
    }

    @Override
    public <X> ValueExtractor<X> getExtractor(JavaType<X> javaType) {
        return new BasicExtractor<X>(javaType, this) {
            @Override
            protected X doExtract(ResultSet rs, int paramIndex, WrapperOptions options)
                    throws SQLException {
                String value = rs.getString(paramIndex);
                return rs.wasNull() ? null : javaType.wrap(value, options);
            }

            @Override
            protected X doExtract(CallableStatement statement, int index, WrapperOptions options)
                    throws SQLException {
                String value = statement.getString(index);
                return statement.wasNull() ? null : javaType.wrap(value, options);
            }

            @Override
            protected X doExtract(CallableStatement statement, String name, WrapperOptions options)
                    throws SQLException {
                String value = statement.getString(name);
                return statement.wasNull() ? null : javaType.wrap(value, options);
            }
        };
    }
}