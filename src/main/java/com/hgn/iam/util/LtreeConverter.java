package com.hgn.iam.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.postgresql.util.PGobject;

import java.sql.SQLException;

@Converter(autoApply = false)
public class LtreeConverter implements AttributeConverter<String, Object> {

    @Override
    public Object convertToDatabaseColumn(String attribute) {
        if (attribute == null) {
            return null;
        }
        PGobject pgObject = new PGobject();
        pgObject.setType("ltree");
        try {
            pgObject.setValue(attribute);
        } catch (SQLException e) {
            throw new IllegalArgumentException("Invalid ltree value: " + attribute, e);
        }
        return pgObject;
    }

    @Override
    public String convertToEntityAttribute(Object dbData) {
        if (dbData == null) {
            return null;
        }
        if (dbData instanceof PGobject pg) {
            return pg.getValue();
        }
        return dbData.toString();
    }
}
